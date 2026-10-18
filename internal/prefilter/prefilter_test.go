package prefilter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/task"
)

func groups() []inventory.Group {
	return []inventory.Group{
		{Fields: map[string]string{"vendor": "Palo Alto Networks", "product": "PAN-OS", "version": "11.2.13-h2"}, Count: 67, Collected: map[string][]string{"usage": {"Internet edge firewalls, GlobalProtect portal"}}},
		{Fields: map[string]string{"vendor": "Cisco", "product": "ASA", "version": ""}, Count: 2},
		{Fields: map[string]string{"vendor": "", "product": "Keycloak", "version": "26.1"}, Count: 1, Collected: map[string][]string{"interest": {"authentication bypass"}}},
		{Fields: map[string]string{"vendor": "OpenBSD", "product": "OpenBSD", "version": "7.8"}, Count: 1},
	}
}

func TestTokens(t *testing.T) {
	got := strings.Join(Tokens("PAN-OS 11.2.13-h2: Sicherheitslücke in Firewalls"), "|")
	if got != "pan|os|11|2|13|h2|sicherheitslücke|in|firewalls" {
		t.Errorf("tokens: %s", got)
	}
}

func TestBuildTargets(t *testing.T) {
	ts := BuildTargets(groups(), []string{"# watch list", "Fortinet FortiGate (various)", "GlobalProtect portal on abc.example"})
	if len(ts) != 6 {
		t.Fatalf("targets: %+v", ts)
	}
	if ts[3].Label != "OpenBSD 7.8" || strings.Join(ts[3].Keywords, ",") != "openbsd" {
		t.Errorf("vendor equal to product: %+v", ts[3])
	}
	if ts[0].Label != "Palo Alto Networks PAN-OS 11.2.13-h2" || !strings.Contains(ts[0].Text, "Usage: Internet edge firewalls") {
		t.Errorf("group target: %+v", ts[0])
	}
	want := []string{"palo alto", "pan os", "alto", "palo", "paloalto", "pan", "panos"}
	if strings.Join(ts[0].Keywords, ",") != strings.Join(want, ",") {
		t.Errorf("keywords: %v", ts[0].Keywords)
	}
	for _, kw := range ts[0].Keywords {
		if kw == "networks" {
			t.Error("stopword kept as keyword")
		}
	}
	if ts[1].Label != "Cisco ASA" || strings.Join(ts[1].Keywords, ",") != "asa,cisco" {
		t.Errorf("cisco: %+v", ts[1])
	}
	if ts[4].Label != "Fortinet FortiGate (various)" || strings.Join(ts[4].Keywords, ",") != "fortigate,fortinet" {
		t.Errorf("free text: %+v", ts[4])
	}
	if strings.Join(ts[5].Keywords, ",") != "globalprotect" {
		t.Errorf("free text 2: %+v", ts[5])
	}
}

func TestLexical(t *testing.T) {
	ts := BuildTargets(groups(), nil)
	for text, want := range map[string]string{
		"Palo Alto Networks patches PAN-OS zero-day":                 "Palo Alto Networks PAN-OS 11.2.13-h2",
		"Sicherheitslücke in PAN-OS 11.2 von Palo Alto":              "Palo Alto Networks PAN-OS 11.2.13-h2",
		"PANOS management interface exposed":                         "Palo Alto Networks PAN-OS 11.2.13-h2",
		"Cisco's ASA appliances under attack":                        "Cisco ASA",
		"Keycloak 26.2 fixes open redirect":                          "Keycloak 26.1",
		"Company networks see more phishing; pancakes for breakfast": "",
		"Japan and the Asahi brewery hit by ransomware":              "",
		"": "",
	} {
		got, kw, ok := Lexical(ts, text)
		if (want == "") == ok || got.Label != want || (ok && kw == "") {
			t.Errorf("%q: got %q kw=%q ok=%v, want %q", text, got.Label, kw, ok, want)
		}
	}
}

func cfg(mode string, threshold float64) Config {
	return Config{
		Filter:   &task.Prefilter{Mode: mode, Threshold: threshold, Image: "localhost/ais-prefilter:test", Timeout: 10 * time.Second, MaxTokens: 128},
		TaskName: "vuln-watch", RunID: "r1", Dialect: container.DockerDialect{}, UID: 1001, GID: 1001,
	}
}

func items() []Item {
	return []Item{
		{Key: "k1", Text: "Palo Alto fixes PAN-OS flaw"},
		{Key: "k2", Text: "Hospital adopts new scheduling software"},
		{Key: "k3", Text: "Firewall vendor patches VPN portal bypass"},
	}
}

func TestScoreMixesKeywordAndModel(t *testing.T) {
	fake := runtime.NewFakeDocker()
	var seenArgv []string
	fake.OnRun = func(argv []string) (string, int, bool) {
		seenArgv = argv
		return `{"v":1,"model":"test-model","dim":8,"ms":3,"scores":[{"key":"k2","score":0.12,"best":"g0"},{"key":"k3","score":0.61,"best":"g0"}],"usage":{"cpu_usec":5400000,"mem_peak":812000000}}`, 0, true
	}
	dir := t.TempDir()
	dec, info := Score(context.Background(), fake, cfg("enforce", 0.45), dir, BuildTargets(groups(), nil), items())
	if len(dec) != 3 {
		t.Fatalf("decisions: %+v", dec)
	}
	if !dec[0].Keep || dec[0].Reason != "keyword:palo alto" || !IsKeyword(dec[0].Reason) || dec[0].Match != "Palo Alto Networks PAN-OS 11.2.13-h2" {
		t.Errorf("keyword item: %+v", dec[0])
	}
	if dec[1].Keep || dec[1].Reason != ReasonModel || dec[1].Score != 0.12 {
		t.Errorf("dropped item: %+v", dec[1])
	}
	if !dec[2].Keep || dec[2].Reason != ReasonModel || dec[2].Match != "Palo Alto Networks PAN-OS 11.2.13-h2" {
		t.Errorf("kept by score: %+v", dec[2])
	}
	if info.CPU != 5400*time.Millisecond || info.MemPeak != 812000000 {
		t.Errorf("usage: %v %d", info.CPU, info.MemPeak)
	}
	if info.Model != "test-model" || info.Keyword != 1 || info.Scored != 2 || info.Kept != 2 || info.Dropped != 1 || info.Err != "" {
		t.Errorf("info: %+v", info)
	}
	// The container only sees the items the keyword pass left.
	raw, err := os.ReadFile(filepath.Join(dir, "in.json"))
	if err != nil {
		t.Fatal(err)
	}
	var in input
	_ = json.Unmarshal(raw, &in)
	if in.V != 1 || len(in.Items) != 2 || in.Items[0].Key != "k2" || len(in.Targets) != 4 || in.MaxTokens != 128 {
		t.Errorf("in.json: %+v", in)
	}
	argv := strings.Join(seenArgv, " ")
	for _, want := range []string{"--network none", "--read-only", "--cap-drop=ALL", dir + ":/work:ro", "--memory 2g", "--label io.ais.role=prefilter", "localhost/ais-prefilter:test"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q: %s", want, argv)
		}
	}
	if strings.Contains(argv, "--network ais") || strings.Contains(argv, ":/work:rw") || strings.Contains(argv, "--env CLAUDE") {
		t.Errorf("argv: %s", argv)
	}
	if _, err := os.Stat(filepath.Join(dir, "out.json")); err != nil {
		t.Error("out.json not kept")
	}
}

func TestScoreKeepsOnError(t *testing.T) {
	for name, fake := range map[string]*runtime.Fake{
		"exit 1":   {Stderr: "Traceback: boom", ExitCode: 1},
		"not json": {Stdout: "<html>"},
		"protocol": {Stdout: `{"v":2,"scores":[]}`},
		"missing":  {Stdout: `{"v":1,"model":"m","dim":1,"scores":[{"key":"k2","score":0.1,"best":"g0"}]}`},
	} {
		fake.EngineName, fake.Dial = "docker", container.DockerDialect{}
		dec, info := Score(context.Background(), fake, cfg("enforce", 0.45), t.TempDir(), BuildTargets(groups(), nil), items())
		if info.Err == "" {
			t.Errorf("%s: no error reported", name)
		}
		if name == "missing" {
			// k2 was scored and legitimately dropped; k3 got no score and is kept.
			if dec[1].Keep || dec[1].Reason != ReasonModel || !dec[2].Keep || dec[2].Reason != ReasonError {
				t.Errorf("missing: %+v", dec)
			}
			continue
		}
		for _, d := range dec {
			if !d.Keep {
				t.Errorf("%s: dropped %+v", name, d)
			}
		}
	}
	// No runtime, no targets: kept too, and no container.
	dec, info := Score(context.Background(), nil, cfg("enforce", 0.45), t.TempDir(), BuildTargets(groups(), nil), items())
	if info.Err == "" || !dec[1].Keep || dec[1].Reason != ReasonError {
		t.Errorf("nil runtime: %+v %+v", dec, info)
	}
	fake := runtime.NewFakeDocker()
	dec, info = Score(context.Background(), fake, cfg("enforce", 0.45), t.TempDir(), nil, items())
	if info.Err == "" || !dec[1].Keep || len(fake.Calls) != 0 {
		t.Errorf("no targets: %+v %+v calls %v", dec, info, fake.Calls)
	}
}

func TestScoreThresholdEdgeAndTimeout(t *testing.T) {
	fake := runtime.NewFakeDocker()
	fake.OnRun = func([]string) (string, int, bool) {
		return `{"v":1,"model":"m","dim":1,"scores":[{"key":"k2","score":0.45,"best":"g1"},{"key":"k3","score":0.4499,"best":"g1"}]}`, 0, true
	}
	dec, _ := Score(context.Background(), fake, cfg("shadow", 0.45), t.TempDir(), BuildTargets(groups(), nil), items())
	if !dec[1].Keep || dec[2].Keep || dec[1].Match != "Cisco ASA" {
		t.Errorf("edge: %+v", dec)
	}
	slow := runtime.NewFakeDocker()
	slow.BlockUntilCancel = true
	c := cfg("enforce", 0.45)
	c.Filter.Timeout = 50 * time.Millisecond
	dec, info := Score(context.Background(), slow, c, t.TempDir(), BuildTargets(groups(), nil), items())
	if !strings.Contains(info.Err, "exceeded") || !dec[1].Keep {
		t.Errorf("timeout: %+v %+v", info, dec)
	}
}

func TestNoKeywordsOnlyModel(t *testing.T) {
	fake := runtime.NewFakeDocker()
	fake.OnRun = func([]string) (string, int, bool) {
		return `{"v":1,"model":"m","dim":1,"scores":[{"key":"k1","score":0.9,"best":"g0"},{"key":"k2","score":0.1,"best":"g0"},{"key":"k3","score":0.1,"best":"g0"}]}`, 0, true
	}
	c := cfg("enforce", 0.45)
	off := false
	c.Filter.Keywords = &off
	dec, info := Score(context.Background(), fake, c, t.TempDir(), BuildTargets(groups(), nil), items())
	if info.Keyword != 0 || info.Scored != 3 || dec[0].Reason != ReasonModel || !dec[0].Keep {
		t.Errorf("%+v %+v", info, dec)
	}
}

func TestItemText(t *testing.T) {
	if ItemText(" T ", "") != "T" || ItemText("T", " s ") != "T. s" {
		t.Error("ItemText")
	}
}
