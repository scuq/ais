package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const rssDoc = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>The Hacker News</title>
<item><title>PAN-OS &lt;b&gt;flaw&lt;/b&gt; exploited</title><link>https://example.test/a</link><guid isPermaLink="false">a-1</guid>
<description><![CDATA[<p>Attackers exploit &amp; patch now.</p>]]></description><pubDate>Fri, 17 Oct 2026 08:00:00 +0000</pubDate></item>
<item><title>Older</title><link>https://example.test/b</link><pubDate>Thu, 16 Oct 2026 08:00:00 GMT</pubDate></item>
</channel></rss>`

const atomDoc = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>heise Security</title>
<entry><title>Keycloak update</title><id>urn:x:1</id><updated>2026-10-17T09:30:00Z</updated>
<link rel="alternate" href="https://example.test/k"/><summary>Fixes an account takeover.</summary></entry></feed>`

const rdfDoc = `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>RDF feed</title></channel><item><title>RDF item</title><link>https://example.test/r</link><dc:date>2026-10-17T07:00:00+02:00</dc:date></item></rdf:RDF>`

const kevDoc = `{"title":"CISA KEV","vulnerabilities":[{"cveID":"CVE-2026-0322","vendorProject":"Palo Alto Networks","product":"PAN-OS","vulnerabilityName":"Code Injection","dateAdded":"2026-10-14","shortDescription":"Root RCE.","notes":"https://security.paloaltonetworks.com/CVE-2026-0322 ; https://nvd.nist.gov/vuln/detail/CVE-2026-0322","knownRansomwareCampaignUse":"Known"}]}`

func TestParseFormats(t *testing.T) {
	rss, err := Parse([]byte(rssDoc), "https://feeds.example/x")
	if err != nil || len(rss) != 2 {
		t.Fatalf("rss: %v %+v", err, rss)
	}
	if rss[0].Title != "PAN-OS flaw exploited" || rss[0].Link != "https://example.test/a" || rss[0].Source != "The Hacker News" || rss[0].Summary != "Attackers exploit & patch now." || rss[0].Published.Hour() != 8 || rss[0].Key == rss[1].Key {
		t.Errorf("rss item: %+v", rss[0])
	}
	if rss[1].Title != "Older" {
		t.Error("items must sort newest first")
	}
	atom, err := Parse([]byte(atomDoc), "https://heise.example/")
	if err != nil || len(atom) != 1 || atom[0].Link != "https://example.test/k" || atom[0].Source != "heise Security" || atom[0].Published.IsZero() {
		t.Errorf("atom: %v %+v", err, atom)
	}
	rdf, err := Parse([]byte(rdfDoc), "https://rdf.example/")
	if err != nil || len(rdf) != 1 || rdf[0].Published.UTC().Hour() != 5 {
		t.Errorf("rdf: %v %+v", err, rdf)
	}
	kev, err := Parse([]byte(kevDoc), "https://www.cisa.gov/kev.json")
	if err != nil || len(kev) != 1 || kev[0].Source != "CISA KEV" || kev[0].Link != "https://security.paloaltonetworks.com/CVE-2026-0322" || !strings.HasPrefix(kev[0].Title, "KEV CVE-2026-0322: Palo Alto Networks PAN-OS") || !strings.HasPrefix(kev[0].Summary, "Used in ransomware") {
		t.Errorf("kev: %v %+v", err, kev)
	}
	// A control character inside a text node does not lose the feed.
	if got, err := Parse([]byte(strings.Replace(rssDoc, "Older", "Old\x0ber", 1)), "https://x.example/"); err != nil || len(got) != 2 || got[1].Title != "Older" {
		t.Errorf("control char: %v %+v", err, got)
	}
	for name, body := range map[string]string{"html": "<!DOCTYPE html><html><body>Loading</body></html>", "json": `{"foo": 1}`, "empty": ""} {
		if _, err := Parse([]byte(body), "https://x.example/"); err == nil {
			t.Errorf("%s accepted as a feed", name)
		}
	}
}

func TestParseDateAndCut(t *testing.T) {
	for _, s := range []string{"Fri, 17 Oct 2026 08:00:00 +0000", "Fri, 17 Oct 2026 08:00:00 GMT", "2026-10-17T08:00:00Z", "2026-10-17"} {
		if parseDate(s).IsZero() {
			t.Errorf("date %q not parsed", s)
		}
	}
	if parseDate("Thu, 01 Oct 26 12:00:00 +0000").Year() != 2026 {
		t.Error("two-digit year not parsed")
	}
	// A broken pubDate falls back to dc:date.
	if d := firstDate("Thu, 01 Jun 2023 18:23:19 GMT+0100 oops", "2023-06-01T18:23:19Z"); d.Year() != 2023 {
		t.Errorf("fallback date: %v", d)
	}
	if !parseDate("yesterday").IsZero() {
		t.Error("garbage date parsed")
	}
	if got := cut(strings.Repeat("ä", 300), 10); len([]rune(got)) != 10 {
		t.Errorf("cut: %q", got)
	}
}

func TestFetchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rss":
			w.Write([]byte(rssDoc))
		case "/kev":
			w.Write([]byte(kevDoc))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	res := FetchAll(context.Background(), []string{srv.URL + "/rss", srv.URL + "/missing", srv.URL + "/kev"}, 5*time.Second)
	if len(res) != 3 || len(res[0].Items) != 2 || res[1].Err == nil || !strings.Contains(res[1].Err.Error(), "404") || len(res[2].Items) != 1 {
		t.Errorf("%+v", res)
	}
}
