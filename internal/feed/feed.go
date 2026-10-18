// Package feed fetches RSS, Atom and RDF feeds and the CISA KEV JSON on the
// host, so that a run gets the list of new items instead of reading the
// feed pages itself. The host remembers what it has handed to a run; the
// model only sees what is new.
package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Item is one feed entry, reduced to what a prompt needs.
type Item struct {
	// Key identifies the item across fetches: a hash of its GUID, else
	// its link, else its title.
	Key       string    `json:"key"`
	Title     string    `json:"title"`
	Link      string    `json:"link"`
	Source    string    `json:"source"`
	Summary   string    `json:"summary,omitempty"`
	Published time.Time `json:"published"`
}

// Result is what one feed returned.
type Result struct {
	URL   string
	Items []Item
	Err   error
}

// Limits. A feed past them is cut, not refused: one noisy feed must not
// stop the others.
const (
	MaxItemsPerFeed = 300
	MaxSummary      = 240
	MaxBody         = 8 << 20
	userAgent       = "ais (+https://github.com/scuq/ais) feed reader"
)

// FetchAll fetches every URL, at most four at a time, and returns one
// Result per URL in the given order. A failed feed has Err set and no
// items.
func FetchAll(ctx context.Context, urls []string, timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	out := make([]Result, len(urls))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := Fetch(ctx, client, u)
			out[i] = Result{URL: u, Items: items, Err: err}
		}(i, u)
	}
	wg.Wait()
	return out
}

// Fetch reads one feed.
func Fetch(ctx context.Context, client *http.Client, rawURL string) ([]Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, application/json;q=0.9, */*;q=0.5")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, err
	}
	return Parse(body, rawURL)
}

// Parse decodes a feed body. It accepts RSS 2.0, Atom, RDF (RSS 1.0) and
// the CISA Known Exploited Vulnerabilities JSON.
func Parse(body []byte, rawURL string) ([]Item, error) {
	trim := strings.TrimSpace(string(body))
	if strings.HasPrefix(trim, "{") {
		return parseKEV(body, rawURL)
	}
	var f xmlFeed
	dec := xml.NewDecoder(strings.NewReader(stripControl(trim)))
	dec.Strict = false
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a feed: %v", err)
	}
	source := firstNonEmpty(strings.TrimSpace(f.Channel.Title), strings.TrimSpace(f.Title), hostOf(rawURL))
	var out []Item
	add := func(title, link, guid, summary string, dates ...string) {
		title = clean(title)
		link = strings.TrimSpace(link)
		if title == "" && link == "" {
			return
		}
		out = append(out, Item{
			Key: key(firstNonEmpty(strings.TrimSpace(guid), link, title)), Title: title, Link: link, Source: source,
			Summary: cut(clean(summary), MaxSummary), Published: firstDate(dates...),
		})
	}
	for _, it := range append(f.Channel.Items, f.Items...) {
		add(it.Title, it.Link, it.GUID, it.Description, it.PubDate, it.Date)
	}
	for _, e := range f.Entries {
		add(e.Title, e.href(), e.ID, firstNonEmpty(e.Summary, e.Content), e.Published, e.Updated)
	}
	if len(out) == 0 && len(f.Channel.Items)+len(f.Items)+len(f.Entries) == 0 && f.XMLName.Local != "rss" && f.XMLName.Local != "feed" && f.XMLName.Local != "RDF" {
		return nil, fmt.Errorf("not a feed: root element <%s>", f.XMLName.Local)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Published.After(out[j].Published) })
	if len(out) > MaxItemsPerFeed {
		out = out[:MaxItemsPerFeed]
	}
	return out, nil
}

type xmlFeed struct {
	XMLName xml.Name
	Title   string `xml:"title"`
	Channel struct {
		Title string    `xml:"title"`
		Items []xmlItem `xml:"item"`
	} `xml:"channel"`
	Items   []xmlItem  `xml:"item"` // RDF puts items next to the channel
	Entries []xmlEntry `xml:"entry"`
}

type xmlItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"date"` // dc:date in RDF
}

type xmlEntry struct {
	Title     string `xml:"title"`
	ID        string `xml:"id"`
	Updated   string `xml:"updated"`
	Published string `xml:"published"`
	Summary   string `xml:"summary"`
	Content   string `xml:"content"`
	Links     []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
}

// href prefers the alternate link of an Atom entry.
func (e xmlEntry) href() string {
	for _, l := range e.Links {
		if l.Rel == "" || l.Rel == "alternate" {
			return l.Href
		}
	}
	if len(e.Links) > 0 {
		return e.Links[0].Href
	}
	if strings.HasPrefix(e.ID, "http") {
		return e.ID
	}
	return ""
}

// kev is the CISA Known Exploited Vulnerabilities catalog.
type kev struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
		Notes             string `json:"notes"`
		KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

var urlInText = regexp.MustCompile(`https?://[^\s;,]+`)

func parseKEV(body []byte, rawURL string) ([]Item, error) {
	var k kev
	if err := json.Unmarshal(body, &k); err != nil {
		return nil, fmt.Errorf("not a KEV catalog: %v", err)
	}
	if k.Vulnerabilities == nil {
		return nil, fmt.Errorf("not a KEV catalog: no vulnerabilities list")
	}
	var out []Item
	for _, v := range k.Vulnerabilities {
		link := "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + url.QueryEscape(v.CVEID)
		if u := urlInText.FindString(v.Notes); u != "" {
			link = u
		}
		summary := v.ShortDescription
		if strings.EqualFold(v.KnownRansomware, "Known") {
			summary = "Used in ransomware campaigns. " + summary
		}
		out = append(out, Item{
			Key:    key("kev:" + v.CVEID),
			Title:  strings.TrimSpace(fmt.Sprintf("KEV %s: %s %s — %s", v.CVEID, v.VendorProject, v.Product, v.VulnerabilityName)),
			Link:   link,
			Source: "CISA KEV", Summary: cut(clean(summary), MaxSummary), Published: parseDate(v.DateAdded),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Published.After(out[j].Published) })
	if len(out) > MaxItemsPerFeed {
		out = out[:MaxItemsPerFeed]
	}
	return out, nil
}

var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano, time.RFC822Z, time.RFC822,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 06 15:04:05 -0700", "Mon, 02 Jan 06 15:04:05 MST", // CISA writes a two-digit year
	"Mon, 02 Jan 2006 15:04:05 GMT-0700", // CERT.at writes "GMT+0100"
	"2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05", "2006-01-02",
}

// firstDate returns the first candidate that parses; a feed often has a
// broken pubDate next to a clean dc:date.
func firstDate(candidates ...string) time.Time {
	for _, c := range candidates {
		if t := parseDate(c); !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// parseDate tries the date formats feeds use. An unknown format gives the
// zero time, which sorts last.
func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// stripControl removes the control characters that XML forbids and that
// some feeds carry in their text, so that one stray byte does not lose the
// whole feed.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}

var tagRE = regexp.MustCompile(`<[^>]*>`)

// clean strips markup and collapses whitespace.
func clean(s string) string {
	s = html.UnescapeString(tagRE.ReplaceAllString(s, " "))
	s = html.UnescapeString(s) // double-encoded descriptions are common
	return strings.Join(strings.Fields(s), " ")
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

func key(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.TrimPrefix(u.Host, "www.")
	}
	return rawURL
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
