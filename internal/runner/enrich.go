package runner

import (
	"fmt"
	"strings"

	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/task"
)

// Enrich applies the task's enrich rules to a clear result: for every
// element selected by a rule's path, the inventory records whose match
// fields equal the element's fields are attached under the attach name.
// This is the host-side join that puts device identity back without it
// ever having been in the model's context.
func Enrich(doc any, rules []task.EnrichRule, recs []inventory.Record) (any, error) {
	for _, rule := range rules {
		elems, err := selectPath(doc, rule.Path)
		if err != nil {
			return doc, err
		}
		for _, e := range elems {
			obj, ok := e.(map[string]any)
			if !ok {
				continue
			}
			for name, fields := range rule.Attach {
				obj[name] = matchRecords(obj, rule.Match, fields, recs)
			}
		}
	}
	return doc, nil
}

func matchRecords(obj map[string]any, match map[string]string, fields []string, recs []inventory.Record) []any {
	out := []any{}
	for _, r := range recs {
		hit := true
		for resField, invField := range match {
			v, ok := obj[resField]
			if !ok || fmt.Sprint(v) != r.Fields[invField] {
				hit = false
				break
			}
		}
		if !hit {
			continue
		}
		attached := map[string]any{}
		for _, f := range fields {
			attached[f] = r.Fields[f]
		}
		out = append(out, attached)
	}
	return out
}

// selectPath resolves "findings", "a.b[]" or "a.b" to the elements it names:
// array elements when the target is an array, the single object otherwise.
func selectPath(doc any, path string) ([]any, error) {
	cur := []any{doc}
	for _, seg := range strings.Split(path, ".") {
		seg = strings.TrimSuffix(seg, "[]")
		if seg == "" {
			continue
		}
		var next []any
		for _, c := range cur {
			obj, ok := c.(map[string]any)
			if !ok {
				continue
			}
			v, ok := obj[seg]
			if !ok {
				continue
			}
			if arr, ok := v.([]any); ok {
				next = append(next, arr...)
			} else {
				next = append(next, v)
			}
		}
		cur = next
	}
	return cur, nil
}
