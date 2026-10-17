package inventory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/scuq/ais/assets"
)

func TestParsePanoramaCSV(t *testing.T) {
	devs, err := ParsePanoramaCSV(bytes.NewReader(assets.Read("examples/panorama-managed-devices.csv")))
	if err != nil {
		t.Fatal(err)
	}
	// fw01 has two vsys rows and appears once.
	if len(devs) != 3 || devs[0].Name != "fw01.cyberdyne.systems" || devs[0].IPv4 != "10.1.0.1" || devs[0].Version != "11.1.4" || devs[0].Model != "PA-3420" || devs[0].Serial != "012345678901" || devs[0].HAState != "active" {
		t.Fatalf("%+v", devs)
	}
	sum := PanoramaSummary(devs)
	if len(sum) != 2 || sum[0].Model != "PA-3420" || sum[0].Count != 2 || sum[1].Model != "PA-VM" || sum[1].Version != "11.2.4-h4" {
		t.Errorf("summary: %+v", sum)
	}
	// A BOM and another column order are fine; a missing version column is not.
	if d, err := ParsePanoramaCSV(strings.NewReader("\ufeffSoftware Version,Device Name\n1.0,x\n")); err != nil || len(d) != 1 || d[0].Version != "1.0" {
		t.Errorf("reordered: %+v %v", d, err)
	}
	// A UTF-8 BOM in front of a quoted header, as Panorama writes it, and a
	// UTF-16LE export, as Excel saves it, both parse.
	quoted := "\"Device Name\",\"Software Version\"\n\"fw\",\"11.1.4\"\n"
	if d, err := ParsePanoramaCSV(strings.NewReader("\ufeff" + quoted)); err != nil || len(d) != 1 || d[0].Name != "fw" {
		t.Errorf("bom before quote: %+v %v", d, err)
	}
	var u16 []byte
	u16 = append(u16, 0xFF, 0xFE)
	for _, r := range quoted {
		u16 = append(u16, byte(r), 0)
	}
	if d, err := ParsePanoramaCSV(bytes.NewReader(u16)); err != nil || len(d) != 1 || d[0].Version != "11.1.4" {
		t.Errorf("utf-16: %+v %v", d, err)
	}
	if d, err := ParsePanoramaCSV(bytes.NewReader(u16[2:])); err != nil || len(d) != 1 {
		t.Errorf("utf-16 without bom: %+v %v", d, err)
	}
	// An HA pair is one row with ";" between the peers; single columns apply to both.
	pair, err := ParsePanoramaCSV(strings.NewReader("\"Device Name\",\"Model\",\"Serial Number\",\"IP Address IPv4\",\"HA Cluster State\",\"Software Version\"\n" +
		"\"fw-a;fw-b\",\"PA-3440\",\"001;002\",\"198.51.100.98;198.51.100.99\",\"active;passive\",\"11.2.13-h2\"\n"))
	if err != nil || len(pair) != 2 || pair[0].Name != "fw-a" || pair[1].Name != "fw-b" || pair[1].Serial != "002" || pair[1].IPv4 != "198.51.100.99" || pair[1].HAState != "passive" || pair[1].Model != "PA-3440" || pair[0].Version != "11.2.13-h2" {
		t.Errorf("ha pair: %+v %v", pair, err)
	}
	if sum := PanoramaSummary(pair); len(sum) != 1 || sum[0].Count != 2 {
		t.Errorf("ha summary: %+v", sum)
	}
	if _, err := ParsePanoramaCSV(strings.NewReader("Device Name,Model\nx,PA\n")); err == nil {
		t.Error("missing version column accepted")
	}
	if _, err := ParsePanoramaCSV(strings.NewReader("Device Name,Software Version\n")); err == nil {
		t.Error("empty export accepted")
	}
}

func TestMergePanorama(t *testing.T) {
	devs, _ := ParsePanoramaCSV(bytes.NewReader(assets.Read("examples/panorama-managed-devices.csv")))
	doc, err := ParseDocument(strings.NewReader("# fw01.cyberdyne.systems\n```json\n{\"hostname\": \"fw01.cyberdyne.systems\", \"ip\": \"10.9.9.9\", \"site\": \"earth\", \"vendor\": \"Palo Alto Networks\", \"product\": \"PAN-OS\", \"version\": \"11.1.3\"}\n```\n\n## Usage\n\nEdge, internet facing.\n\n# gone.cyberdyne.systems\n```json\n{\"hostname\": \"gone.cyberdyne.systems\", \"product\": \"PAN-OS\", \"source\": \"panorama\"}\n```\n\n# Keycloak\n```json\n{\"product\": \"Keycloak\"}\n```\n"))
	if err != nil {
		t.Fatal(err)
	}
	st := MergePanorama(doc, devs, false)
	if st.Added != 2 || st.Updated != 1 || st.Unchanged != 0 || st.Pruned != 0 || len(doc.Entries) != 5 {
		t.Fatalf("stats %+v entries %d", st, len(doc.Entries))
	}
	fw01 := doc.Find("fw01.cyberdyne.systems")
	if fw01.Fields["ip"] != "10.1.0.1" || fw01.Fields["version"] != "11.1.4" || fw01.Fields["site"] != "earth" || fw01.Fields["serial"] != "012345678901" || fw01.Fields["source"] != PanoramaSource || fw01.Section("usage") == nil {
		t.Errorf("fw01 after merge: %+v", fw01.Fields)
	}
	if strings.Join(fw01.Keys, ",") != "hostname,ip,site,vendor,product,version,model,serial,ha_state,source" {
		t.Errorf("key order: %v", fw01.Keys)
	}
	// A second import changes nothing; with prune the stale entry goes,
	// Keycloak (not from Panorama) stays.
	st = MergePanorama(doc, devs, true)
	if st.Added != 0 || st.Updated != 0 || st.Unchanged != 3 || st.Pruned != 1 || doc.Find("gone.cyberdyne.systems") != nil || doc.Find("Keycloak") == nil {
		t.Errorf("second import: %+v, %d entries", st, len(doc.Entries))
	}
	// A device matched by serial follows a rename; an IP that went away is removed.
	devs[0].Name, devs[0].IPv4 = "fw01-new.cyberdyne.systems", ""
	st = MergePanorama(doc, devs[:1], false)
	if st.Updated != 1 || doc.Find("fw01.cyberdyne.systems").Fields["hostname"] != "fw01-new.cyberdyne.systems" {
		t.Errorf("rename by serial: %+v", st)
	}
	if _, has := doc.Find("fw01.cyberdyne.systems").Fields["ip"]; has {
		t.Error("stale ip kept")
	}
	out := doc.Render()
	if _, err := ParseDocument(bytes.NewReader(out)); err != nil {
		t.Errorf("render after merge: %v\n%s", err, out)
	}
}

func TestMergePanoramaRoles(t *testing.T) {
	devs, _ := ParsePanoramaCSV(bytes.NewReader(assets.Read("examples/panorama-managed-devices.csv")))
	doc, _ := ParseDocument(strings.NewReader("# Internet edge firewalls\n```json\n{\"vendor\": \"Palo Alto Networks\", \"product\": \"PAN-OS\", \"version\": \"11.1.4\", \"count\": 2}\n```\n\n## Usage\n\nEdge.\n\n# PAN-OS 10.2.9\n```json\n{\"product\": \"PAN-OS\", \"version\": \"10.2.9\", \"count\": 9, \"source\": \"panorama\"}\n```\n"))
	st := MergePanoramaRoles(doc, devs, false)
	if st.Added != 2 || st.Updated != 0 || st.Pruned != 0 || len(doc.Entries) != 4 {
		t.Fatalf("stats %+v entries %d", st, len(doc.Entries))
	}
	e := doc.Find("PAN-OS 11.1.4")
	if e == nil || e.Fields["count"] != "2" || e.Fields["models"] != "PA-3420" || e.Fields["source"] != PanoramaSource || e.Fields["hostname"] != "" {
		t.Errorf("version entry: %+v", e)
	}
	if strings.Join(e.Keys, ",") != "vendor,product,version,count,models,source" {
		t.Errorf("keys: %v", e.Keys)
	}
	if doc.Find("Internet edge firewalls").Fields["count"] != "2" {
		t.Error("hand-written role entry touched")
	}
	// Upgrades move the counts; prune drops a version that is gone and
	// keeps the hand-written entry.
	devs[2].Version = "11.1.4"
	st = MergePanoramaRoles(doc, devs, true)
	if st.Updated != 1 || st.Pruned != 2 || doc.Find("PAN-OS 11.1.4").Fields["count"] != "3" || doc.Find("PAN-OS 11.2.4-h4") != nil || doc.Find("PAN-OS 10.2.9") != nil || doc.Find("Internet edge firewalls") == nil {
		t.Errorf("re-import: %+v, entries %d", st, len(doc.Entries))
	}
	if _, err := ParseDocument(bytes.NewReader(doc.Render())); err != nil {
		t.Error(err)
	}
}
