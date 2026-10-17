// Package sink delivers finished results and alerts to the outside: a
// generic webhook, NATS JetStream and Splunk HEC. The Dispatcher drains the
// store's delivery queue with retries, backoff and a dead-letter state, so
// a sink outage never loses a result and never blocks a run.
package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/secret"
)

// Event is what a sink receives.
type Event struct {
	Kind       string    `json:"kind"` // result | alert | digest
	Task       string    `json:"task"`
	RunID      string    `json:"run_id"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	Error      string    `json:"error,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
	// Result is the clear, enriched structured output (result events).
	Result any `json:"result,omitempty"`
	// Leaks lists the inventory fields whose real values appeared in model
	// output (for leak alerts). The values themselves never leave the host.
	Leaks []string `json:"leaks,omitempty"`
	// Digest summarises a window of runs (digest events). Meta then holds
	// the sums over those runs.
	Digest *Digest `json:"digest,omitempty"`
	Meta   Meta    `json:"meta"`
}

// Meta is run metadata attached to every event.
type Meta struct {
	// Model is the model that did most of the work.
	// Models lists each model that the run used, with the highest cost first.
	Model  string   `json:"model"`
	Models []string `json:"models,omitempty"`
	Tokens Tokens   `json:"tokens"`
	// Billing is "subscription": CostUSD is Claude Code's list-price
	// estimate, not an invoice.
	Billing    string  `json:"billing"`
	CostUSD    float64 `json:"cost_usd"`
	NumTurns   int     `json:"num_turns"`
	DurationMS int64   `json:"duration_ms"`
	TaskHash   string  `json:"task_hash"`
	Engine     string  `json:"engine"`
	AISVersion string  `json:"ais_version"`
	Host       string  `json:"host"`
}

// Tokens is the token usage of one run, summed over all models.
type Tokens struct {
	Input         int64 `json:"input"`
	Output        int64 `json:"output"`
	CacheRead     int64 `json:"cache_read"`
	CacheCreation int64 `json:"cache_creation"`
}

// In returns the tokens that the models consumed as context: Input plus
// CacheRead and CacheCreation.
func (t Tokens) In() int64 { return t.Input + t.CacheRead + t.CacheCreation }

// Out returns the output tokens.
func (t Tokens) Out() int64 { return t.Output }

// Sink delivers events.
type Sink interface {
	Name() string
	Type() string
	Deliver(ctx context.Context, ev Event) error
}

// Skipper is a sink that declines some events by policy. Skip returns the
// reason, or "" to deliver. The dispatcher records a declined delivery as
// skipped and never retries it.
type Skipper interface {
	Skip(ev Event) string
}

// skipEmpty wraps a sink with skipEmpty: true. It declines a result whose
// findings array is empty.
type skipEmpty struct{ Sink }

func (s skipEmpty) Skip(ev Event) string {
	if ev.Kind == "result" && EmptyFindings(ev.Result) {
		return "no findings"
	}
	return ""
}

// EmptyFindings reports whether result has a findings array with no
// element. A result without a findings array is not empty.
func EmptyFindings(result any) bool {
	m, ok := result.(map[string]any)
	if !ok {
		return false
	}
	arr, ok := m["findings"].([]any)
	return ok && len(arr) == 0
}

// Permanent marks an error that retrying cannot fix (a 4xx, a bad config).
type Permanent struct{ Err error }

func (p Permanent) Error() string { return p.Err.Error() }
func (p Permanent) Unwrap() error { return p.Err }

// IsPermanent reports whether err should go straight to dead-letter.
func IsPermanent(err error) bool {
	var p Permanent
	return errors.As(err, &p)
}

// Build constructs a sink from config. With skipEmpty the sink also
// implements Skipper.
func Build(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	s, err := build(name, cfg, secrets)
	if err != nil {
		return nil, err
	}
	if cfg.SkipEmpty {
		return skipEmpty{s}, nil
	}
	return s, nil
}

func build(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	switch cfg.Type {
	case "webhook":
		return newWebhook(name, cfg, secrets)
	case "splunk_hec":
		return newSplunk(name, cfg, secrets)
	case "nats":
		return newNATS(name, cfg, secrets)
	case "webex":
		return newWebex(name, cfg, secrets)
	}
	return nil, fmt.Errorf("sink %q: unknown type %q", name, cfg.Type)
}

// BuildAll constructs every configured sink.
func BuildAll(cfgs map[string]config.SinkConfig, secrets secret.Store) (map[string]Sink, error) {
	out := map[string]Sink{}
	for name, c := range cfgs {
		s, err := Build(name, c, secrets)
		if err != nil {
			return nil, err
		}
		out[name] = s
	}
	return out, nil
}

func httpClient(cfg config.SinkConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in per sink
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// post sends a body and classifies the response: 2xx ok, 429/5xx retry,
// other 4xx permanent.
func post(ctx context.Context, client *http.Client, url string, headers map[string]string, contentType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Permanent{err}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "ais")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	default:
		return Permanent{fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))}
	}
}

var tmplFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"now": func() string { return time.Now().UTC().Format(time.RFC3339) },
}

func expandHeaders(h map[string]string, secrets secret.Store) (map[string]string, error) {
	out := make(map[string]string, len(h))
	for k, v := range h {
		ev, err := secret.Expand(v, secrets)
		if err != nil {
			return nil, err
		}
		out[k] = ev
	}
	return out, nil
}

// --- webhook -------------------------------------------------------------

type webhook struct {
	name    string
	url     string
	headers map[string]string
	body    *template.Template
	client  *http.Client
}

func newWebhook(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	url, err := secret.Expand(cfg.URL, secrets)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", name, err)
	}
	headers, err := expandHeaders(cfg.Headers, secrets)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", name, err)
	}
	body := cfg.Body
	if body == "" {
		body = "{{ json . }}"
	}
	tmpl, err := template.New(name).Funcs(tmplFuncs).Parse(body)
	if err != nil {
		return nil, fmt.Errorf("sink %q: body template: %w", name, err)
	}
	return &webhook{name: name, url: url, headers: headers, body: tmpl, client: httpClient(cfg)}, nil
}

func (w *webhook) Name() string { return w.name }
func (w *webhook) Type() string { return "webhook" }

func (w *webhook) Deliver(ctx context.Context, ev Event) error {
	var b bytes.Buffer
	if err := w.body.Execute(&b, ev); err != nil {
		return Permanent{fmt.Errorf("body template: %w", err)}
	}
	ct := "application/json"
	if !json.Valid(b.Bytes()) {
		ct = "text/plain; charset=utf-8"
	}
	return post(ctx, w.client, w.url, w.headers, ct, b.Bytes())
}

// --- splunk HEC ------------------------------------------------------------

type splunk struct {
	name       string
	url        string
	token      string
	sourcetype *template.Template
	source     *template.Template
	index      string
	host       string
	split      string
	client     *http.Client
}

func newSplunk(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	url, err := secret.Expand(cfg.URL, secrets)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", name, err)
	}
	token := ""
	if cfg.TokenSecret != "" {
		token, err = secrets.Get(cfg.TokenSecret)
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", name, err)
		}
	} else if v := cfg.Headers["Authorization"]; v != "" {
		if token, err = secret.Expand(strings.TrimPrefix(v, "Splunk "), secrets); err != nil {
			return nil, fmt.Errorf("sink %q: %w", name, err)
		}
	}
	if token == "" {
		return nil, fmt.Errorf("sink %q: splunk_hec needs tokenSecret", name)
	}
	st, err := template.New("st").Funcs(tmplFuncs).Parse(orDefault(cfg.Sourcetype, "ais:result"))
	if err != nil {
		return nil, fmt.Errorf("sink %q: sourcetype: %w", name, err)
	}
	src, err := template.New("src").Funcs(tmplFuncs).Parse(orDefault(cfg.Source, "ais:{{ .Task }}"))
	if err != nil {
		return nil, fmt.Errorf("sink %q: source: %w", name, err)
	}
	return &splunk{name: name, url: url, token: token, sourcetype: st, source: src, index: cfg.Index, host: cfg.Host, split: cfg.Split, client: httpClient(cfg)}, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (s *splunk) Name() string { return s.name }
func (s *splunk) Type() string { return "splunk_hec" }

func render(t *template.Template, ev Event) (string, error) {
	var b strings.Builder
	err := t.Execute(&b, ev)
	return b.String(), err
}

// Deliver sends one HEC event, or one per element of the split field,
// concatenated in a single request as HEC accepts.
func (s *splunk) Deliver(ctx context.Context, ev Event) error {
	sourcetype, err := render(s.sourcetype, ev)
	if err != nil {
		return Permanent{err}
	}
	source, err := render(s.source, ev)
	if err != nil {
		return Permanent{err}
	}
	host := s.host
	if host == "" {
		host = ev.Meta.Host
	}
	var payloads []any
	if s.split != "" && ev.Kind == "result" {
		if m, ok := ev.Result.(map[string]any); ok {
			if arr, ok := m[s.split].([]any); ok {
				for _, el := range arr {
					payloads = append(payloads, map[string]any{
						"kind": ev.Kind, "task": ev.Task, "run_id": ev.RunID, "finished_at": ev.FinishedAt,
						s.split[:len(s.split)-boolToInt(strings.HasSuffix(s.split, "s"))]: el, "meta": ev.Meta,
					})
				}
			}
		}
	}
	if payloads == nil {
		payloads = []any{ev}
	}
	var b bytes.Buffer
	for _, p := range payloads {
		hec := map[string]any{
			"event":      p,
			"sourcetype": sourcetype,
			"source":     source,
			"host":       host,
			"time":       float64(ev.FinishedAt.UnixNano()) / 1e9,
		}
		if s.index != "" {
			hec["index"] = s.index
		}
		if err := json.NewEncoder(&b).Encode(hec); err != nil {
			return Permanent{err}
		}
	}
	return post(ctx, s.client, s.url, map[string]string{"Authorization": "Splunk " + s.token}, "application/json", b.Bytes())
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
