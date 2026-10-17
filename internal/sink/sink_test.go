package sink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/secret"
	"github.com/scuq/ais/internal/store"
)

func event() Event {
	return Event{Kind: "result", Task: "vuln-watch", RunID: "r1", State: "succeeded", FinishedAt: time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC),
		Result: map[string]any{"findings": []any{map[string]any{"product": "PAN-OS", "severity": "critical"}, map[string]any{"product": "FortiOS", "severity": "high"}}},
		Meta:   Meta{Model: "m", CostUSD: 0.5, Host: "h"}}
}

func TestWebhook(t *testing.T) {
	var got []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
	}))
	defer srv.Close()
	s, err := Build("hook", config.SinkConfig{Type: "webhook", URL: srv.URL, Headers: map[string]string{"X-Token": "${secret:tok}"}}, secret.Memory{"tok": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(context.Background(), event()); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("X-Token") != "s3cret" || hdr.Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", hdr)
	}
	var ev Event
	if err := json.Unmarshal(got, &ev); err != nil || ev.RunID != "r1" {
		t.Errorf("body %s err %v", got, err)
	}
}

func TestWebhookTemplateAndStatusClasses(t *testing.T) {
	var code atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(code.Load()))
	}))
	defer srv.Close()
	s, _ := Build("hook", config.SinkConfig{Type: "webhook", URL: srv.URL, Body: `{"text":"{{ .Task }} {{ .State }}"}`}, secret.Memory{})
	code.Store(503)
	if err := s.Deliver(context.Background(), event()); err == nil || IsPermanent(err) {
		t.Errorf("503 should be a retryable error, got %v", err)
	}
	code.Store(400)
	if err := s.Deliver(context.Background(), event()); !IsPermanent(err) {
		t.Errorf("400 should be permanent, got %v", err)
	}
	code.Store(204)
	if err := s.Deliver(context.Background(), event()); err != nil {
		t.Error(err)
	}
}

func TestSplunkSplit(t *testing.T) {
	var got []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()
	s, err := Build("splunk", config.SinkConfig{Type: "splunk_hec", URL: srv.URL + "/services/collector", TokenSecret: "hec", Sourcetype: "xx:vulnerability:notification", Host: "testhost", Index: "sec", Split: "findings"}, secret.Memory{"hec": "ABC"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(context.Background(), event()); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk ABC" {
		t.Errorf("auth %q", auth)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 HEC events, got %d: %s", len(lines), got)
	}
	var hec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hec); err != nil {
		t.Fatal(err)
	}
	if hec["sourcetype"] != "xx:vulnerability:notification" || hec["host"] != "testhost" || hec["index"] != "sec" || hec["source"] != "ais:vuln-watch" {
		t.Errorf("envelope %v", hec)
	}
	if hec["time"].(float64) != float64(event().FinishedAt.Unix()) {
		t.Errorf("time %v", hec["time"])
	}
	ev := hec["event"].(map[string]any)
	if ev["finding"].(map[string]any)["product"] != "PAN-OS" || ev["run_id"] != "r1" {
		t.Errorf("event %v", ev)
	}
}

func TestDispatcherRetryAndDead(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	_ = st.InsertRun(ctx, store.Run{ID: "r1", Task: "t", State: store.StateRunning, StartedAt: now})
	_ = st.FinishRun(ctx, store.Run{ID: "r1", State: store.StateSucceeded, FinishedAt: now})
	_ = st.SaveResult(ctx, "r1", "t", now, []byte(`{"a":1}`), []byte(`{"a":2}`))
	_ = st.EnqueueDelivery(ctx, "r1", "flaky", "result", now)
	_ = st.EnqueueDelivery(ctx, "r1", "missing", "result", now)

	var calls atomic.Int32
	code := atomic.Int32{}
	code.Store(503)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(code.Load()))
	}))
	defer srv.Close()
	flaky, _ := Build("flaky", config.SinkConfig{Type: "webhook", URL: srv.URL}, secret.Memory{})
	clock := now
	d := &Dispatcher{Store: st, Sinks: map[string]Sink{"flaky": flaky}, Cfg: config.DeliveryConfig{MaxAttempts: 3, Backoff: config.BackoffConfig{Initial: time.Minute, Max: time.Hour}}, Now: func() time.Time { return clock }}

	n, err := d.Once(ctx)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	dels, _ := st.DeliveriesOf(ctx, "r1")
	byName := map[string]store.Delivery{}
	for _, x := range dels {
		byName[x.Sink] = x
	}
	if byName["missing"].State != store.DeliveryDead {
		t.Errorf("unconfigured sink should be dead: %+v", byName["missing"])
	}
	if byName["flaky"].State != store.DeliveryPending || byName["flaky"].Attempt != 1 || !byName["flaky"].NextAt.After(now) {
		t.Errorf("flaky after 503: %+v", byName["flaky"])
	}
	// Not due yet.
	clock = now.Add(30 * time.Second)
	if n, _ := d.Once(ctx); n != 0 {
		t.Error("retried before backoff elapsed")
	}
	// Due; succeed this time.
	code.Store(200)
	clock = now.Add(3 * time.Minute)
	if n, _ := d.Once(ctx); n != 1 {
		t.Error("retry not attempted")
	}
	dels, _ = st.DeliveriesOf(ctx, "r1")
	for _, x := range dels {
		if x.Sink == "flaky" && x.State != store.DeliveryDelivered {
			t.Errorf("flaky not delivered: %+v", x)
		}
	}
	if calls.Load() != 2 {
		t.Errorf("calls %d", calls.Load())
	}
	// Dead after max attempts.
	_ = st.EnqueueDelivery(ctx, "r1", "flaky", "result", clock)
	code.Store(500)
	for i := 0; i < 3; i++ {
		clock = clock.Add(3 * time.Hour)
		_, _ = d.Once(ctx)
	}
	dels, _ = st.DeliveriesOf(ctx, "r1")
	last := dels[len(dels)-1]
	if last.State != store.DeliveryDead || last.Attempt != 3 {
		t.Errorf("expected dead after 3 attempts: %+v", last)
	}
}

func TestBackoffBounds(t *testing.T) {
	cfg := config.BackoffConfig{Initial: time.Minute, Max: 10 * time.Minute}
	for attempt, floor := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 10: 10 * time.Minute} {
		d := Backoff(cfg, attempt)
		if d < floor || d > floor+floor/4 {
			t.Errorf("attempt %d: %s outside [%s, %s]", attempt, d, floor, floor+floor/4)
		}
	}
}

func TestWebexIncomingWebhook(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		if r.Header.Get("Authorization") != "" {
			t.Error("incoming webhook must not carry a bearer")
		}
	}))
	defer srv.Close()
	s, err := Build("webex", config.SinkConfig{Type: "webex", URL: srv.URL + "/v1/webhooks/incoming/abc", MaxItems: 1}, secret.Memory{})
	if err != nil {
		t.Fatal(err)
	}
	ev := SampleEvent("vuln-watch")
	if err := s.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	md, _ := got["markdown"].(string)
	for _, want := range []string{
		"🔴 **ais vuln-watch**: 2 finding(s) (1 critical, 1 high)",
		"🔴 **Palo Alto Networks PAN-OS — Authentication bypass on the management interface**",
		"**Your version:** 11.1.4 — affected: < 11.1.5", "**New version:** 11.1.5", "**CVE:** CVE-2026-0001",
		"**Criticality:** CRITICAL / CVSS 9.8 / Exploited in the wild",
		"**Links:** [security.paloaltonetworks.com](https://security.paloaltonetworks.com/)",
		"**Devices (2):** fw01.example, fw02.example", "**Action:** Upgrade to 11.1.5.",
		"**Published:** 2026-10-07; updated 2026-10-08. Previously unreported in this watch.", "… and 1 more",
		"· claude-opus-5-5 · 86k in / 6.0k out · subscription (est. $0.42)_",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	if _, ok := got["roomId"]; ok {
		t.Error("roomId set in webhook mode")
	}
	if _, ok := got["attachments"]; ok {
		t.Error("card attached without card: true")
	}
}

func TestWebexBotCardAndAlert(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		auth = r.Header.Get("Authorization")
	}))
	defer srv.Close()
	if _, err := Build("webex", config.SinkConfig{Type: "webex", URL: srv.URL + "/v1/messages", TokenSecret: "tok"}, secret.Memory{"tok": "T"}); err == nil {
		t.Error("bot mode without roomId accepted")
	}
	if _, err := Build("webex", config.SinkConfig{Type: "webex", URL: srv.URL + "/v1/messages"}, secret.Memory{}); err == nil {
		t.Error("non-webhook url without token accepted")
	}
	s, err := Build("webex", config.SinkConfig{Type: "webex", URL: srv.URL + "/v1/messages", TokenSecret: "tok", RoomID: "room1", Card: true}, secret.Memory{"tok": "T"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(context.Background(), SampleEvent("vuln-watch")); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer T" || got["roomId"] != "room1" {
		t.Errorf("bot headers/body: %q %v", auth, got["roomId"])
	}
	att, _ := got["attachments"].([]any)
	if len(att) != 1 {
		t.Fatalf("attachments: %v", got["attachments"])
	}
	card := att[0].(map[string]any)["content"].(map[string]any)
	if card["type"] != "AdaptiveCard" || len(card["body"].([]any)) < 4 || len(card["actions"].([]any)) != 2 {
		t.Errorf("card: %v", card)
	}
	// A finding without the optional fields still renders every required line.
	minimal := Event{Kind: "result", Task: "vuln-watch", RunID: "r1", State: "succeeded", FinishedAt: time.Now(),
		Result: map[string]any{"findings": []any{map[string]any{"product": "FortiOS", "installed_version": "7.4.5", "severity": "high", "cve_ids": []any{"CVE-2026-0002", "CVE-2026-0003"}, "summary": "s"}}}}
	md := WebexMarkdown("t", minimal, 10)
	for _, want := range []string{"🟠 **FortiOS — CVE-2026-0002, CVE-2026-0003**", "**Your version:** 7.4.5\n", "**New version:** none yet", "**Criticality:** HIGH\n"} {
		if !strings.Contains(md, want) {
			t.Errorf("minimal markdown missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "**Links:**") || strings.Contains(md, "**Published:**") || strings.Contains(md, "**Action:**") {
		t.Errorf("minimal markdown has empty optional lines:\n%s", md)
	}
	// Alerts render too.
	alert := Event{Kind: "alert", Task: "vuln-watch", RunID: "r9", State: "leaked", Reason: "leak", Error: "2 real value(s) appeared", Leaks: []string{"hostname"}, FinishedAt: time.Now()}
	if err := s.Deliver(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if md := got["markdown"].(string); !strings.Contains(md, "⚠️") || !strings.Contains(md, "Leaked fields: hostname") {
		t.Errorf("alert markdown: %s", md)
	}
	// No findings.
	empty := SampleEvent("vuln-watch")
	empty.Result = map[string]any{"findings": []any{}}
	_ = s.Deliver(context.Background(), empty)
	if md := got["markdown"].(string); !strings.Contains(md, "✅") {
		t.Errorf("empty markdown: %s", md)
	}
}

func TestCodeSpans(t *testing.T) {
	cases := map[string]string{
		"Associated IPs: 203.0.113.14, 198.51.100.114 and 192.0.2.234.": "Associated IPs: `203.0.113.14`, `198.51.100.114` and `192.0.2.234`.",
		"see https://security.paloaltonetworks.com/CVE-2026-0322.":      "see `https://security.paloaltonetworks.com/CVE-2026-0322`.",
		"scanned from 10.0.0.0/8 and 1.2.3.4:443":                       "scanned from `10.0.0.0/8` and `1.2.3.4:443`",
		"already `1.2.3.4` in code":                                     "already `1.2.3.4` in code",
		"CVSS 4.0: 8.6, PAN-OS 11.2.13-h2, Threat ID 510044":            "CVSS 4.0: 8.6, PAN-OS 11.2.13-h2, Threat ID 510044",
		"": "",
	}
	for in, want := range cases {
		if got := codeSpans(in); got != want {
			t.Errorf("codeSpans(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestCostLine(t *testing.T) {
	ev := event()
	ev.Meta.Billing = config.Billing
	if got := costLine(ev); got != "m · subscription (est. $0.50)" {
		t.Errorf("no tokens: %q", got)
	}
	ev.Meta.Models = []string{"claude-opus-5-5", "claude-haiku-5-5"}
	ev.Meta.Tokens = Tokens{Input: 122711, Output: 20946, CacheRead: 55694, CacheCreation: 16542}
	if got := costLine(ev); got != "claude-opus-5-5, claude-haiku-5-5 · 194k in / 20k out · subscription (est. $0.50)" {
		t.Errorf("with usage: %q", got)
	}
	ev.Meta.Model, ev.Meta.Models, ev.Meta.Tokens = "", nil, Tokens{}
	if got := costLine(ev); got != "subscription (est. $0.50)" {
		t.Errorf("bare: %q", got)
	}
	card := WebexCard("t", event(), 10)
	footer, _ := card["body"].([]any)
	last, _ := footer[len(footer)-1].(map[string]any)
	if text, _ := last["text"].(string); !strings.HasSuffix(text, " · m · subscription (est. $0.50)") {
		t.Errorf("card footer: %q", text)
	}
}

func TestHumanTokens(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1.0k", 5996: "6.0k", 12345: "12k", 194_000: "194k", 1_234_567: "1.2M", 12_000_000: "12M"} {
		if got := humanTokens(n); got != want {
			t.Errorf("%d: got %q want %q", n, got, want)
		}
	}
}

func TestSkipEmpty(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	plain, _ := Build("plain", config.SinkConfig{Type: "webhook", URL: srv.URL}, secret.Memory{})
	if _, ok := plain.(Skipper); ok {
		t.Error("sink without skipEmpty implements Skipper")
	}
	quiet, _ := Build("quiet", config.SinkConfig{Type: "webex", URL: srv.URL + "/v1/webhooks/incoming/abc", SkipEmpty: true}, secret.Memory{})
	sk, ok := quiet.(Skipper)
	if !ok || quiet.Type() != "webex" || quiet.Name() != "quiet" {
		t.Fatalf("skipEmpty sink: Skipper=%v type=%s name=%s", ok, quiet.Type(), quiet.Name())
	}
	empty := event()
	empty.Result = map[string]any{"findings": []any{}}
	noArray := event()
	noArray.Result = map[string]any{"status": "ok"}
	alert := Event{Kind: "alert", Task: "t", RunID: "r1", State: "failed", FinishedAt: time.Now()}
	for name, c := range map[string]struct {
		ev   Event
		want string
	}{"findings": {event(), ""}, "empty": {empty, "no findings"}, "no array": {noArray, ""}, "alert": {alert, ""}} {
		if got := sk.Skip(c.ev); got != c.want {
			t.Errorf("%s: Skip=%q want %q", name, got, c.want)
		}
	}

	// The dispatcher records a skipped delivery and never calls the sink.
	st, err := store.Open(filepath.Join(t.TempDir(), "ais.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	_ = st.InsertRun(ctx, store.Run{ID: "r1", Task: "t", State: store.StateRunning, StartedAt: now})
	_ = st.FinishRun(ctx, store.Run{ID: "r1", State: store.StateSucceeded, FinishedAt: now})
	_ = st.SaveResult(ctx, "r1", "t", now, []byte(`{"findings":[]}`), []byte(`{"findings":[]}`))
	_ = st.EnqueueDelivery(ctx, "r1", "quiet", "result", now)
	_ = st.EnqueueDelivery(ctx, "r1", "plain", "result", now)
	d := &Dispatcher{Store: st, Sinks: map[string]Sink{"quiet": quiet, "plain": plain}, Cfg: config.DeliveryConfig{MaxAttempts: 3}, Now: func() time.Time { return now }}
	if n, err := d.Once(ctx); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	dels, _ := st.DeliveriesOf(ctx, "r1")
	for _, x := range dels {
		switch x.Sink {
		case "quiet":
			if x.State != store.DeliverySkipped || x.LastError != "no findings" || x.Attempt != 1 {
				t.Errorf("quiet: %+v", x)
			}
		case "plain":
			if x.State != store.DeliveryDelivered {
				t.Errorf("plain: %+v", x)
			}
		}
	}
	if calls.Load() != 1 {
		t.Errorf("sink calls %d, want 1 (plain only)", calls.Load())
	}
	// A skipped row that is reset is skipped again, not retried as an error.
	if _, err := st.ResetDeliveries(ctx, "r1", "quiet", now); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Once(ctx)
	dels, _ = st.DeliveriesOf(ctx, "r1")
	for _, x := range dels {
		if x.Sink == "quiet" && x.State != store.DeliverySkipped {
			t.Errorf("quiet after reset: %+v", x)
		}
	}
}

func TestWebexUpdateAndIoCs(t *testing.T) {
	ev := Event{Kind: "result", Task: "vuln-watch", RunID: "r1", State: "succeeded", FinishedAt: time.Now(),
		Result: map[string]any{"findings": []any{
			map[string]any{"vendor": "Palo Alto Networks", "product": "PAN-OS", "title": "Management interface root RCE", "cve_ids": []any{"CVE-2026-0322"},
				"severity": "critical", "cvss": 8.6, "exploited": true, "fixed_version": "11.2.13-h3", "installed_version": "11.2.13-h2",
				"summary": "Long summary that an update must not repeat.", "affected": "All PA-Series.", "action": "Patch now.",
				"published": "2026-10-14; updated 2026-10-16", "previously_reported": true,
				"update":      "Now exploited in the wild; CISA KEV entry added. Three new attacker addresses published.",
				"iocs":        []any{"66.42.72.14", "208.83.239.114", "evil.example"},
				"source_urls": []any{"https://security.paloaltonetworks.com/CVE-2026-0322"},
				"devices":     []any{map[string]any{"hostname": "fw01.example"}}},
			map[string]any{"vendor": "Fortinet", "product": "FortiOS", "title": "SSL VPN flaw", "cve_ids": []any{"CVE-2026-0002"}, "severity": "high",
				"source_urls": []any{"https://fortiguard.fortinet.com/"}, "summary": "New finding.", "previously_reported": false, "update": nil,
				"iocs": []any{"203.0.113.9"}},
		}}}
	md := WebexMarkdown("ais vuln-watch", ev, 10)
	for _, want := range []string{
		"🔴 **ais vuln-watch**: 2 finding(s) (1 critical, 1 high; 1 update(s))",
		"🔁 **Update: Palo Alto Networks PAN-OS — Management interface root RCE**",
		"**What's new:** Now exploited in the wild; CISA KEV entry added.",
		"**Criticality:** CRITICAL / CVSS 8.6 / Exploited in the wild",
		"**New version:** 11.2.13-h3",
		"**IoCs:** `66.42.72.14`, `208.83.239.114`, `evil.example`",
		"**Devices (1):** fw01.example",
		"🟠 **Fortinet FortiOS — SSL VPN flaw**",
		"**Summary:** New finding.",
		"**IoCs:** `203.0.113.9`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	for _, unwanted := range []string{"Long summary", "**Affected:** All PA-Series", "**Action:** Patch now", "**Your version:** 11.2.13-h2", "Previously reported in this watch"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("update repeats %q:\n%s", unwanted, md)
		}
	}
	// A repeated finding without an update text is rendered in full.
	full := ev.Result.(map[string]any)["findings"].([]any)[0].(map[string]any)
	full["update"] = ""
	if md := WebexMarkdown("ais vuln-watch", ev, 10); !strings.Contains(md, "**Your version:** 11.2.13-h2") || !strings.Contains(md, "Previously reported in this watch; new information.") {
		t.Errorf("fallback to full block missing:\n%s", md)
	}
	full["update"] = "x"
	card := WebexCard("ais vuln-watch", ev, 10)
	raw, _ := json.Marshal(card)
	if !strings.Contains(string(raw), "Update: Palo Alto Networks PAN-OS") || !strings.Contains(string(raw), "What's new: x") || strings.Contains(string(raw), "Long summary") {
		t.Errorf("card: %s", raw)
	}
}
