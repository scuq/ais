//go:build integration

package prefilter

import (
	"context"
	"testing"
	"time"

	"github.com/scuq/ais/internal/container"
	"github.com/scuq/ais/internal/runtime"
	"github.com/scuq/ais/internal/task"
)

// TestScoreWithRealImage runs the built prefilter image on the self-test
// texts: a related item must score above an unrelated one, and the
// keyword pass must not be needed for it. Needs a container engine and
// the image from 'ais prefilter build'.
func TestScoreWithRealImage(t *testing.T) {
	rt, err := runtime.Detect("auto")
	if err != nil {
		t.Skip(err)
	}
	ref := task.DefaultPrefilterImage
	if exists, _ := rt.ImageExists(context.Background(), ref); !exists {
		t.Skipf("%s is not built", ref)
	}
	dialect, _ := container.DialectFor(rt.Engine())
	off := false
	cfg := Config{
		Filter:   &task.Prefilter{Mode: task.PrefilterEnforce, Threshold: 0.45, Image: ref, Timeout: 3 * time.Minute, MaxTokens: 128, Keywords: &off},
		TaskName: "integration", RunID: "t-" + time.Now().UTC().Format("150405"), Dialect: dialect,
	}
	targets := []Target{{ID: "g0", Label: "PAN-OS", Text: "Palo Alto Networks PAN-OS 11.2. Usage: Internet edge firewalls with GlobalProtect portal"}}
	items := []Item{
		{Key: "related", Text: "Palo Alto Networks patches actively exploited authentication bypass in PAN-OS management interface"},
		{Key: "unrelated", Text: "Recipe: a quick weeknight pasta with lemon and garlic"},
	}
	dec, info := Score(context.Background(), rt, cfg, t.TempDir(), targets, items)
	if info.Err != "" {
		t.Fatalf("prefilter: %s", info.Err)
	}
	if !dec[0].Scored || !dec[1].Scored || dec[0].Score <= dec[1].Score || !dec[0].Keep || dec[1].Keep {
		t.Errorf("decisions: %+v (model %s, %s)", dec, info.Model, info.Duration)
	}
	if info.CPU <= 0 || info.MemPeak <= 0 {
		t.Errorf("the image reported no usage: cpu %v, memory %d", info.CPU, info.MemPeak)
	}
	t.Logf("related %.3f, unrelated %.3f, %s in %s, cpu %s, peak %d MiB", dec[0].Score, dec[1].Score, info.Model, info.Duration, info.CPU, info.MemPeak>>20)
}
