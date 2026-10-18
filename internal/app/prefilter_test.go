package app

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/scuq/ais/internal/store"
)

func TestSetYAMLPath(t *testing.T) {
	src := "# header\nname: t\nfeeds:\n  urls: [https://a.example/rss]   # the feeds\n  maxRunsPerDay: 12\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	if err := setYAMLPath(&doc, []string{"feeds", "prefilter", "mode"}, "enforce", "!!str"); err != nil {
		t.Fatal(err)
	}
	if err := setYAMLPath(&doc, []string{"feeds", "prefilter", "threshold"}, "0.5", "!!float"); err != nil {
		t.Fatal(err)
	}
	if err := setYAMLPath(&doc, []string{"feeds", "prefilter", "mode"}, "shadow", "!!str"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(&doc)
	out := buf.String()
	for _, want := range []string{"# header", "# the feeds", "maxRunsPerDay: 12", "  prefilter:\n    mode: shadow\n    threshold: 0.5\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "mode:") != 1 {
		t.Errorf("mode set twice:\n%s", out)
	}
}

func TestPrefilterStats(t *testing.T) {
	items := []store.FeedItem{
		{Key: "a", Title: "PAN-OS", Link: "https://x/a", Decision: store.DecisionKeep, Reason: "keyword:pan os"},
		{Key: "b", Title: "VPN", Link: "https://x/b/", Decision: store.DecisionKeep, Reason: "model", Score: 0.52, Scored: true},
		{Key: "c", Title: "Bakery", Link: "https://x/c", Decision: store.DecisionDrop, Reason: "model", Score: 0.1, Scored: true},
		{Key: "d", Title: "Kernel", Link: "https://x/d?utm=1", Decision: store.DecisionDrop, Reason: "model", Score: 0.38, Scored: true},
		{Key: "e", Title: "Unscored", Link: "https://x/e", Decision: store.DecisionKeep, Reason: "error"},
	}
	verdicts := modelVerdicts([]store.Result{
		{PseudoJSON: []byte(`{"findings":[{"source_urls":["https://x/b"]},{"source_urls":["https://X/D"]}],"checked":[{"url":"https://x/c","verdict":"product not in inventory"},{"url":"https://x/b","verdict":"reported"}]}`)},
	})
	s := prefilterStats(items, verdicts, 0.45)
	if s.Decided != 5 || s.Keyword != 1 || s.Scored != 3 || s.Unscored != 1 || s.Kept != 3 || s.Dropped != 2 {
		t.Errorf("counts: %+v", s)
	}
	if s.WouldKeep != 3 || s.WouldDrop != 2 || s.Histogram[5] != 1 || s.Histogram[1] != 1 || s.Histogram[3] != 1 {
		t.Errorf("threshold view: %+v", s)
	}
	if len(s.Evaluated) != 3 || s.Reported != 2 || s.ReportedDropped != 1 || s.LowestReported != 0.38 {
		t.Errorf("evaluated: %+v", s)
	}
	if !s.Evaluated[0].Reported || s.Evaluated[0].Key != "d" || s.Evaluated[2].Verdict != "product not in inventory" {
		t.Errorf("order: %+v", s.Evaluated)
	}
	// A higher threshold than every reported score is flagged.
	if s2 := prefilterStats(items, verdicts, 0.3); s2.ReportedDropped != 0 || s2.WouldDrop != 1 {
		t.Errorf("lower threshold: %+v", s2)
	}
}
