package aisctl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scuq/ais/assets"
)

// invTestEnv gives an Env without a config.yaml, so that the default
// redaction policy applies and the inventory path comes from --file.
func invTestEnv(t *testing.T) (*Env, *strings.Builder, string) {
	t.Helper()
	var out strings.Builder
	e, _, _ := testEnv(t)
	e.Out = &out
	path := filepath.Join(t.TempDir(), "inv.mdj")
	// The example plus one device with a bare hostname, as in many networks.
	doc := string(assets.Read("examples/inventory.mdj")) + "\n# nx00fw-01\n\n```json\n{\"hostname\": \"nx00fw-01\", \"ip\": \"198.51.100.7\", \"product\": \"PAN-OS\"}\n```\n\n## Usage\n\nnx00fw-01 is the lab box, peer of nx00fw-02.\n"
	_ = os.WriteFile(path, []byte(doc), 0o600)
	return e, &out, path
}

func TestInventoryListAndEdit(t *testing.T) {
	e, out, path := invTestEnv(t)
	ctx := context.Background()
	if err := runInventory(ctx, e, []string{"list", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "Internet edge firewalls") || !strings.Contains(s, "PAN-OS") || strings.Contains(s, "vpn01.cyberdyne.systems") || strings.Contains(s, "10.1.0.5") || !strings.Contains(s, "ica01.ploreqlar.flfgrzf") || strings.Contains(s, "nx00fw-01") || strings.Contains(s, "198.51.100.7") {
		t.Errorf("list must pseudonymize:\n%s", s)
	}
	out.Reset()
	if err := runInventory(ctx, e, []string{"set", "Internet edge firewalls", "version=11.1.6", "count=3", "--interest", "Everything.", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if err := runInventory(ctx, e, []string{"add", "Panorama", "vendor=Palo Alto Networks", "product=Panorama", "version=11.1.6", "--usage", "Management.", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if err := runInventory(ctx, e, []string{"rm", "NetScaler ADC", "--file", path}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	for _, want := range []string{"\"version\": \"11.1.6\",\n  \"count\": \"3\"", "## Interest\n\nEverything.", "# Panorama\n", "## Usage\n\nManagement.", "## Usage\n\nEdge firewalls, internet facing."} {
		if !strings.Contains(s, want) {
			t.Errorf("file missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "NetScaler") || strings.Contains(s, "unauthenticated remote attack vector") {
		t.Errorf("stale content:\n%s", s)
	}
	if m, _ := filepath.Glob(path + ".bak-*"); len(m) != 3 {
		t.Errorf("backups: %v", m)
	}
	for name, args := range map[string][]string{
		"set unknown":   {"set", "nope", "version=1"},
		"add existing":  {"add", "Keycloak", "version=1"},
		"bad count":     {"set", "Keycloak", "count=many"},
		"not key=value": {"set", "Keycloak", "version"},
		"rm unknown":    {"rm", "nope"},
	} {
		if err := runInventory(ctx, e, append(args, "--file", path)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInventoryShowAndApply(t *testing.T) {
	e, out, path := invTestEnv(t)
	ctx := context.Background()
	if err := runInventory(ctx, e, []string{"show", "--file", path}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	if strings.Contains(shown, "vpn01.cyberdyne.systems") || strings.Contains(shown, "10.1.0.5") || strings.Contains(shown, "172.16.1.20") || !strings.Contains(shown, "ica01.ploreqlar.flfgrzf") || !strings.Contains(shown, "## Usage") || strings.Contains(shown, "nx00fw-01") || strings.Contains(shown, "198.51.100.7") || !strings.Contains(shown, "is the lab box, peer of") {
		t.Fatalf("show leaks or lost structure:\n%s", shown)
	}
	// Edit the redacted copy: a new usage text and a new product.
	edited := strings.Replace(shown, "SSL VPN gateway, internet facing.", "SSL VPN gateway, internet facing, MFA enforced.", 1) + "\n# Grafana\n\n```json\n{\"product\": \"Grafana\"}\n```\n"
	draft := filepath.Join(t.TempDir(), "draft.mdj")
	_ = os.WriteFile(draft, []byte(edited), 0o600)
	out.Reset()
	if err := runInventory(ctx, e, []string{"apply", draft, "--file", path}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "\"hostname\": \"vpn01.cyberdyne.systems\"") || !strings.Contains(s, "\"ip\": \"10.1.0.5\"") || !strings.Contains(s, "MFA enforced") || !strings.Contains(s, "# Grafana") || strings.Contains(s, "ploreqlar") || strings.Contains(s, "\"ip\": \"100.") ||
		!strings.Contains(s, "# nx00fw-01\n") || !strings.Contains(s, "\"ip\": \"198.51.100.7\"") || !strings.Contains(s, "nx00fw-01 is the lab box, peer of nx00fw-02.") {
		t.Errorf("apply did not restore real values:\n%s", s)
	}
	// Without a map, apply refuses.
	_ = os.Remove(filepath.Join(e.Home, ".local", "state", "ais", redactMapFile))
	if err := runInventory(ctx, e, []string{"apply", draft, "--file", path}); err == nil {
		t.Error("apply without map accepted")
	}
	// An address in prose outside the policy blocks show unless forced; an
	// address in a field is pseudonymized whatever the policy says.
	_ = os.WriteFile(path, []byte("# x\n```json\n{\"hostname\": \"x.other.example\", \"ip\": \"8.8.4.4\", \"product\": \"P\"}\n```\n\n## Usage\n\nUpstream is 9.9.9.9.\n"), 0o600)
	if err := runInventory(ctx, e, []string{"show", "--file", path}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("uncovered values printed: %v", err)
	}
	out.Reset()
	if err := runInventory(ctx, e, []string{"show", "--force", "--file", path}); err != nil || !strings.Contains(out.String(), "9.9.9.9") || strings.Contains(out.String(), "8.8.4.4") || strings.Contains(out.String(), "x.other.example") {
		t.Errorf("force: %v\n%s", err, out.String())
	}
}

func TestInventoryImportPanorama(t *testing.T) {
	e, out, path := invTestEnv(t)
	ctx := context.Background()
	csvPath := filepath.Join(t.TempDir(), "devices.csv")
	_ = os.WriteFile(csvPath, assets.Read("examples/panorama-managed-devices.csv"), 0o600)
	if err := runInventory(ctx, e, []string{"import", "panorama", csvPath, "--dry-run", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "PA-3420") || !strings.Contains(s, "3 added") || !strings.Contains(s, "dry run") || strings.Contains(s, "10.1.0.1") {
		t.Errorf("dry run output:\n%s", s)
	}
	before, _ := os.ReadFile(path)
	if !strings.Contains(string(before), "# Internet edge firewalls") || strings.Contains(string(before), "fw01") {
		t.Fatal("dry run wrote the file")
	}
	out.Reset()
	if err := runInventory(ctx, e, []string{"import", "panorama", csvPath, "--file", path}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "# fw01.cyberdyne.systems") || !strings.Contains(s, "\"serial\": \"012345678901\"") || !strings.Contains(s, "\"source\": \"panorama\"") || !strings.Contains(s, "# Internet edge firewalls") {
		t.Errorf("import result:\n%s", s)
	}
	// --roles writes version entries with counts and no identities, next to
	// the device entries of the first import.
	if err := runInventory(ctx, e, []string{"import", "panorama", csvPath, "--roles", "--file", path}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if s := string(data); !strings.Contains(s, "# PAN-OS 11.1.4\n") || !strings.Contains(s, "\"count\": \"2\",\n  \"models\": \"PA-3420\"") || !strings.Contains(s, "# PAN-OS 11.2.4-h4\n") {
		t.Errorf("roles import:\n%s", s)
	}
	if err := runInventory(ctx, e, []string{"import", "nope", csvPath, "--file", path}); err == nil {
		t.Error("unknown importer accepted")
	}
}

func TestInventoryWhere(t *testing.T) {
	e, out, path := invTestEnv(t)
	ctx := context.Background()
	// Every PAN-OS entry gets an interest; the regex is case-insensitive here.
	if err := runInventory(ctx, e, []string{"set", "--where", "product~(?i)^pan-os$", "--interest", "Remote only.", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "changed 2 entries") || strings.Contains(s, "nx00fw-01") || !strings.Contains(s, "Internet edge firewalls") {
		t.Errorf("set --where output:\n%s", s)
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "## Interest\n\nRemote only."); n != 2 {
		t.Errorf("interest set %d times:\n%s", n, data)
	}
	// A hostname regex selects the device; a section name selects on its text.
	out.Reset()
	if err := runInventory(ctx, e, []string{"set", "--where", "hostname~^vpn0[0-9]", "--where", "usage~SAML", "site=mars", "--dry-run", "--file", path}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "would change 1 entries: ica01.ploreqlar.flfgrzf") {
		t.Errorf("dry run:\n%s", s)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "mars") {
		t.Error("dry run wrote")
	}
	for name, args := range map[string][]string{
		"no match":        {"set", "--where", "product~^Nope$", "version=1"},
		"bad regex":       {"set", "--where", "product~(", "version=1"},
		"not field~re":    {"set", "--where", "product", "version=1"},
		"title and where": {"set", "Keycloak", "--where", "product~.", "version=1"},
		"rm no match":     {"rm", "--where", "title~^zzz"},
	} {
		if err := runInventory(ctx, e, append(args, "--file", path)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Title regex removes the product-only entries without a version.
	out.Reset()
	if err := runInventory(ctx, e, []string{"rm", "--where", "title~^(GlobalProtect|NetScaler ADC)$", "--file", path}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if s := string(data); strings.Contains(s, "# GlobalProtect") || strings.Contains(s, "# NetScaler ADC") || !strings.Contains(s, "# Keycloak") || !strings.Contains(out.String(), "removed 2 entries") {
		t.Errorf("rm --where:\n%s\n%s", out.String(), s)
	}
}
