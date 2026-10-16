package pseudo

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scuq/ais/internal/inventory"
)

func recs() []inventory.Record {
	return []inventory.Record{
		{Fields: map[string]string{"hostname": "fw01.corp.example", "ip": "10.1.0.1", "product": "PAN-OS", "owner_email": "x@corp.example"}},
		{Fields: map[string]string{"hostname": "fw02.corp.example", "ip": "10.2.0.1", "product": "PAN-OS", "owner_email": "y@corp.example"}},
	}
}

func policy() Policy {
	return Policy{"hostname": Pseudonym, "ip": Pseudonym, "product": Clear, "owner_email": Drop}
}

func TestApplyAndRoundTrip(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	m := NewMap("t", "s1")
	out := Apply(policy(), NewTokenizer(salt, nil), m, nil, recs())
	if len(out) != 2 {
		t.Fatal("records lost")
	}
	r := out[0].Fields
	if _, ok := r["owner_email"]; ok {
		t.Error("dropped field survived")
	}
	if r["product"] != "PAN-OS" {
		t.Error("clear field changed")
	}
	if !strings.HasPrefix(r["hostname"], "host-") || !strings.HasPrefix(r["ip"], "ip-") {
		t.Errorf("token labels wrong: %v", r)
	}
	if r["hostname"] == "fw01.corp.example" {
		t.Error("hostname not tokenized")
	}
	// Stable across tokenizers with the same salt.
	m2 := NewMap("t", "s1")
	out2 := Apply(policy(), NewTokenizer(salt, nil), m2, nil, recs())
	if out2[0].Fields["hostname"] != r["hostname"] {
		t.Error("tokens not stable for the same salt")
	}
	// Different salt, different token.
	m3 := NewMap("t", "s2")
	out3 := Apply(policy(), NewTokenizer([]byte("other-salt-other-salt-other-salt"), nil), m3, nil, recs())
	if out3[0].Fields["hostname"] == r["hostname"] {
		t.Error("tokens identical across salts")
	}

	doc := map[string]any{
		"findings": []any{map[string]any{"host": r["hostname"], "text": "device " + r["hostname"] + " at " + r["ip"] + " is affected"}},
	}
	clear := Depseudonymize(doc, m).(map[string]any)
	f := clear["findings"].([]any)[0].(map[string]any)
	if f["host"] != "fw01.corp.example" {
		t.Errorf("whole-string token not replaced: %v", f["host"])
	}
	if f["text"] != "device fw01.corp.example at 10.1.0.1 is affected" {
		t.Errorf("embedded tokens not replaced: %v", f["text"])
	}
}

func TestLeakCheck(t *testing.T) {
	m := NewMap("t", "s")
	m.Add("host-aaaaaaaa", "hostname", "fw01.corp.example")
	raw := []byte(`{"result":"The firewall FW01.corp.example is vulnerable"}`)
	f := LeakCheck(raw, m, Rules{Literals: []string{"topsecret"}})
	if len(f) != 1 || f[0].Value != "fw01.corp.example" {
		t.Fatalf("expected one finding, got %+v", f)
	}
	if LeakCheck([]byte(`{"result":"host-aaaaaaaa is vulnerable"}`), m, Rules{}) != nil {
		t.Error("token itself flagged as leak")
	}
	if got := LeakCheck([]byte("contains TopSecret here"), m, Rules{Literals: []string{"topsecret"}}); len(got) != 1 {
		t.Error("literal not found case-insensitively")
	}
}

func TestRedactor(t *testing.T) {
	rd, err := NewRedactor(Rules{Domains: []string{"corp.example"}, CIDRs: []string{"10.0.0.0/8"}, Literals: []string{"Project Falcon"}})
	if err != nil {
		t.Fatal(err)
	}
	in := "see fw01.corp.example (10.1.0.1) and public 8.8.8.8 at news.ycombinator.com; project falcon; 2001:db8::1"
	got := rd.Redact(in)
	for _, bad := range []string{"fw01.corp.example", "10.1.0.1", "falcon"} {
		if strings.Contains(strings.ToLower(got), bad) {
			t.Errorf("%q survived: %s", bad, got)
		}
	}
	for _, keep := range []string{"8.8.8.8", "news.ycombinator.com", "2001:db8::1"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q wrongly removed: %s", keep, got)
		}
	}
	var doc any
	_ = json.Unmarshal([]byte(`{"a":["x fw9.corp.example",{"b":"10.9.9.9"}],"n":5}`), &doc)
	out, _ := json.Marshal(rd.RedactDoc(doc))
	if strings.Contains(string(out), "corp.example") || strings.Contains(string(out), "10.9.9.9") || !strings.Contains(string(out), `"n":5`) {
		t.Errorf("RedactDoc: %s", out)
	}
}

func TestPolicyFailsClosed(t *testing.T) {
	if policy().ModeOf("unknown") != Drop {
		t.Error("unknown field must drop")
	}
}
