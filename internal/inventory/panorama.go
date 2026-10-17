package inventory

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

// PanoramaSource marks an entry that the Panorama importer wrote, in the
// field "source", so that a later import can prune devices that are gone.
const PanoramaSource = "panorama"

// PanoramaDevice is one row of the "Managed Devices" CSV export of
// Panorama. Only the columns that an inventory needs are kept.
type PanoramaDevice struct {
	Name, Serial, Model, IPv4, IPv6, Version, HAState string
}

// panoramaColumns maps the export's column names, lowercased, to the
// struct fields. The two required ones are the device name and the
// software version.
var panoramaColumns = map[string]func(d *PanoramaDevice, v string){
	"device name":      func(d *PanoramaDevice, v string) { d.Name = v },
	"serial number":    func(d *PanoramaDevice, v string) { d.Serial = v },
	"model":            func(d *PanoramaDevice, v string) { d.Model = v },
	"ip address ipv4":  func(d *PanoramaDevice, v string) { d.IPv4 = v },
	"ip address ipv6":  func(d *PanoramaDevice, v string) { d.IPv6 = v },
	"software version": func(d *PanoramaDevice, v string) { d.Version = v },
	"ha cluster state": func(d *PanoramaDevice, v string) { d.HAState = v },
}

// ParsePanoramaCSV reads a Panorama "Managed Devices" export. The header
// row names the columns; their order does not matter. A device that
// appears twice (one row per virtual system) is kept once.
func ParsePanoramaCSV(r io.Reader) ([]PanoramaDevice, error) {
	text, err := decodeExport(r)
	if err != nil {
		return nil, fmt.Errorf("panorama csv: %w", err)
	}
	cr := csv.NewReader(strings.NewReader(text))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("panorama csv: header: %w", err)
	}
	setters := make([]func(*PanoramaDevice, string), len(header))
	have := map[string]bool{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		if set, ok := panoramaColumns[h]; ok {
			setters[i] = set
			have[h] = true
		}
	}
	for _, need := range []string{"device name", "software version"} {
		if !have[need] {
			return nil, fmt.Errorf("panorama csv: column %q is missing (is this the Managed Devices export?)", need)
		}
	}
	var out []PanoramaDevice
	seen := map[string]bool{}
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("panorama csv: %w", err)
		}
		var d PanoramaDevice
		for i, v := range row {
			if i < len(setters) && setters[i] != nil {
				setters[i](&d, cleanCell(v))
			}
		}
		if d.Name == "" {
			continue
		}
		for _, peer := range splitHAPair(d) {
			key := strings.ToLower(peer.Serial + "\x00" + peer.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, peer)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("panorama csv: no device rows")
	}
	return out, nil
}

// decodeExport returns the export as UTF-8 text without a byte order mark.
// Panorama and Excel write a UTF-8 BOM or UTF-16, and a BOM in front of the
// first quote would make the CSV reader keep the quotes as text.
func decodeExport(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return string(data[3:]), nil
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUTF16(data[2:], binary.LittleEndian), nil
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUTF16(data[2:], binary.BigEndian), nil
	case len(data) >= 2 && data[1] == 0 && data[0] != 0:
		return decodeUTF16(data, binary.LittleEndian), nil // UTF-16LE without a BOM
	}
	return string(data), nil
}

func decodeUTF16(data []byte, order binary.ByteOrder) string {
	u := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u = append(u, order.Uint16(data[i:]))
	}
	return string(utf16.Decode(u))
}

// cleanCell trims a cell, including the curly quotes that a copy through
// a mail client or a spreadsheet can leave.
func cleanCell(v string) string {
	return strings.Trim(strings.TrimSpace(v), "\"\u201c\u201d")
}

// splitHAPair expands a row that holds an HA pair. Panorama writes both
// peers into one row, with ";" between the two names, serials, addresses
// and states ("fw-a;fw-b", "10.0.0.1;10.0.0.2", "active;passive"). A
// column with one value, such as the model, applies to both peers.
func splitHAPair(d PanoramaDevice) []PanoramaDevice {
	names := splitSemi(d.Name)
	if len(names) < 2 {
		return []PanoramaDevice{d}
	}
	pick := func(s string, i int) string {
		parts := splitSemi(s)
		switch {
		case len(parts) == 0:
			return ""
		case i < len(parts):
			return parts[i]
		}
		return parts[0]
	}
	out := make([]PanoramaDevice, 0, len(names))
	for i, name := range names {
		out = append(out, PanoramaDevice{
			Name: name, Serial: pick(d.Serial, i), Model: pick(d.Model, i), IPv4: pick(d.IPv4, i), IPv6: pick(d.IPv6, i),
			Version: pick(d.Version, i), HAState: pick(d.HAState, i),
		})
	}
	return out
}

// splitSemi splits "a;b" into its trimmed, non-empty parts.
func splitSemi(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ";") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// panoramaKeys is the order of the JSON keys of an imported entry.
var panoramaKeys = []string{"hostname", "ip", "ipv6", "vendor", "product", "version", "model", "serial", "ha_state", "source"}

// Fields returns the inventory values of the device. Empty values are
// left out.
func (d PanoramaDevice) Fields() map[string]string {
	f := map[string]string{
		"hostname": d.Name, "ip": d.IPv4, "ipv6": d.IPv6,
		"vendor": "Palo Alto Networks", "product": "PAN-OS", "version": d.Version,
		"model": d.Model, "serial": d.Serial, "ha_state": d.HAState, "source": PanoramaSource,
	}
	for k, v := range f {
		if v == "" {
			delete(f, k)
		}
	}
	return f
}

// MergeStats says what an import did.
type MergeStats struct {
	Added, Updated, Unchanged, Pruned int
}

// MergePanorama writes the devices into the document. A device matches an
// entry by serial number, else by hostname, else by title. A matched entry
// gets the imported values; its other values and its sections stay. A new
// device becomes a new entry. With prune, entries that the importer wrote
// earlier and that the export no longer has are removed.
func MergePanorama(doc *Document, devs []PanoramaDevice, prune bool) MergeStats {
	var st MergeStats
	matched := map[*Entry]bool{}
	for _, d := range devs {
		e := doc.FindByField("serial", d.Serial)
		if e == nil {
			e = doc.FindByField("hostname", d.Name)
		}
		if e == nil {
			e = doc.Find(d.Name)
		}
		fields := d.Fields()
		if e == nil {
			matched[doc.Add(d.Name, panoramaKeys, fields)] = true
			st.Added++
			continue
		}
		matched[e] = true
		changed := false
		for _, k := range panoramaKeys {
			v, ok := fields[k]
			switch {
			case k == "vendor" || k == "product":
				if _, has := e.Fields[k]; !has {
					e.Set(k, v)
					changed = true
				}
			case ok && e.Fields[k] != v:
				e.Set(k, v)
				changed = true
			case !ok && (k == "ip" || k == "ipv6" || k == "ha_state"):
				if _, has := e.Fields[k]; has {
					e.Unset(k)
					changed = true
				}
			}
		}
		if changed {
			st.Updated++
		} else {
			st.Unchanged++
		}
	}
	if prune {
		kept := doc.Entries[:0]
		for _, e := range doc.Entries {
			if e.Fields["source"] == PanoramaSource && !matched[e] {
				st.Pruned++
				continue
			}
			kept = append(kept, e)
		}
		doc.Entries = kept
	}
	return st
}

// roleKeys is the order of the JSON keys of an imported version entry.
var roleKeys = []string{"vendor", "product", "version", "count", "models", "source"}

// MergePanoramaRoles writes the export as one entry per software version,
// titled "PAN-OS <version>", with the device count and the models, and no
// hostname or address. A re-import moves the counts. With prune, entries
// that the importer wrote earlier and whose version the export no longer
// has are removed. Entries without "source: panorama" are never touched.
func MergePanoramaRoles(doc *Document, devs []PanoramaDevice, prune bool) MergeStats {
	var st MergeStats
	type agg struct {
		count  int
		models map[string]bool
	}
	byVersion := map[string]*agg{}
	var versions []string
	for _, d := range devs {
		a := byVersion[d.Version]
		if a == nil {
			a = &agg{models: map[string]bool{}}
			byVersion[d.Version] = a
			versions = append(versions, d.Version)
		}
		a.count++
		if d.Model != "" {
			a.models[d.Model] = true
		}
	}
	sort.Strings(versions)
	matched := map[*Entry]bool{}
	for _, v := range versions {
		a := byVersion[v]
		models := make([]string, 0, len(a.models))
		for m := range a.models {
			models = append(models, m)
		}
		sort.Strings(models)
		fields := map[string]string{
			"vendor": "Palo Alto Networks", "product": "PAN-OS", "version": v,
			CountField: fmt.Sprintf("%d", a.count), "models": strings.Join(models, ", "), "source": PanoramaSource,
		}
		if v == "" {
			fields["version"] = ""
		}
		title := strings.TrimSpace("PAN-OS " + v)
		e := doc.Find(title)
		if e == nil || e.Fields["source"] != PanoramaSource {
			matched[doc.Add(title, roleKeys, fields)] = true
			st.Added++
			continue
		}
		matched[e] = true
		changed := false
		for _, k := range roleKeys {
			if e.Fields[k] != fields[k] {
				e.Set(k, fields[k])
				changed = true
			}
		}
		if changed {
			st.Updated++
		} else {
			st.Unchanged++
		}
	}
	if prune {
		kept := doc.Entries[:0]
		for _, e := range doc.Entries {
			if e.Fields["source"] == PanoramaSource && !matched[e] {
				st.Pruned++
				continue
			}
			kept = append(kept, e)
		}
		doc.Entries = kept
	}
	return st
}

// PanoramaGroup is one model and version with its device count.
type PanoramaGroup struct {
	Model, Version string
	Count          int
}

// PanoramaSummary counts the devices per model and version, sorted. It
// holds no identity, so it can be shown anywhere.
func PanoramaSummary(devs []PanoramaDevice) []PanoramaGroup {
	idx := map[string]int{}
	var out []PanoramaGroup
	for _, d := range devs {
		k := d.Model + "\x00" + d.Version
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, PanoramaGroup{Model: d.Model, Version: d.Version})
		}
		out[i].Count++
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Model != out[j].Model {
			return out[i].Model < out[j].Model
		}
		return out[i].Version < out[j].Version
	})
	return out
}
