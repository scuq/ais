package pseudo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Redaction modes.
const (
	// HostnameRot13 replaces each letter of a hostname by rot13 (digits,
	// dots and dashes stay), so a host is still recognisably a host.
	HostnameRot13 = "rot13"
	// IPCGNAT maps a private address deterministically into 100.64.0.0/10,
	// so output still parses as an address but names nothing real.
	IPCGNAT = "cgnat"
	// ModeToken uses opaque label-hex tokens (host-1a2b3c4d, ip-5e6f7a8b).
	ModeToken = "token"
	// ModeRedact replaces the value with Replacement (tool output only).
	ModeRedact = "redact"
)

// Redaction is the effective policy: what counts as sensitive (domains,
// address ranges, literals) and how each kind is rewritten.
type Redaction struct {
	Domains      []string `json:"domains"`
	CIDRs        []string `json:"cidrs"`
	Literals     []string `json:"literals"`
	HostnameMode string   `json:"hostnameMode"`
	IPMode       string   `json:"ipMode"`
}

// PrivateCIDRs are the ranges redacted by default: RFC 1918, IPv4 and IPv6
// link-local, and IPv6 unique-local.
var PrivateCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7"}

// DefaultRedaction is the shipped policy.
func DefaultRedaction() Redaction {
	return Redaction{
		Domains:      []string{".cyberdyne.systems"},
		CIDRs:        append([]string(nil), PrivateCIDRs...),
		HostnameMode: HostnameRot13,
		IPMode:       IPCGNAT,
	}
}

// Validate checks modes and ranges.
func (r Redaction) Validate() error {
	switch r.HostnameMode {
	case HostnameRot13, ModeToken:
	default:
		return fmt.Errorf("hostnameMode %q (use: rot13, token)", r.HostnameMode)
	}
	switch r.IPMode {
	case IPCGNAT, ModeToken:
	default:
		return fmt.Errorf("ipMode %q (use: cgnat, token)", r.IPMode)
	}
	for _, c := range r.CIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			return fmt.Errorf("cidr %q: %w", c, err)
		}
	}
	for _, d := range r.Domains {
		if strings.TrimSpace(d) == "" || strings.ContainsAny(d, " /:") {
			return fmt.Errorf("domain %q is not a domain suffix", d)
		}
	}
	return nil
}

// Rules returns the redactor rules for this policy.
func (r Redaction) Rules() Rules {
	return Rules{Domains: r.Domains, CIDRs: r.CIDRs, Literals: r.Literals, HostnameMode: r.HostnameMode, IPMode: r.IPMode}
}

// ApprovalHash is a stable digest of the policy. It is what `aisctl redact
// approve` records; any change to the policy changes the hash and voids
// the approval.
func (r Redaction) ApprovalHash() string {
	norm := Redaction{HostnameMode: r.HostnameMode, IPMode: r.IPMode}
	norm.Domains = sortedClean(r.Domains)
	norm.CIDRs = sortedClean(r.CIDRs)
	norm.Literals = sortedClean(r.Literals)
	b, _ := json.Marshal(norm)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

func sortedClean(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ErrNotApproved means the gate is closed.
var ErrNotApproved = errors.New("redaction policy is not approved: review it with 'aisctl redact test', then run 'aisctl redact approve'")

// CheckApproval compares the recorded hash with the policy.
func CheckApproval(r Redaction, approvedHash string) error {
	if approvedHash == "" {
		return ErrNotApproved
	}
	if approvedHash != r.ApprovalHash() {
		return fmt.Errorf("redaction policy changed since it was approved (approved %s, current %s): review with 'aisctl redact test', then 'aisctl redact approve'", approvedHash, r.ApprovalHash())
	}
	return nil
}

// Rot13 rotates ASCII letters; everything else is unchanged. It is its
// own inverse.
func Rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// CGNATAddress maps an IPv4 address into 100.64.0.0/10 with a keyed hash:
// the same key and address always give the same result, and nothing about
// the real address survives. Returns "" for non-IPv4 input.
func CGNATAddress(key []byte, ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("cgnat:"))
	mac.Write(v4)
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[:4]) & 0x3fffff // 22 host bits
	base := uint32(100)<<24 | uint32(64)<<16
	addr := base | n
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).String()
}

// IsCGNAT reports whether s is an address inside 100.64.0.0/10.
func IsCGNAT(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && cgnatNet.Contains(ip)
}

var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// Coverage reports inventory values the policy would not scrub if they
// appeared in tool output: hostnames outside the configured domains and
// addresses outside the configured ranges.
type Coverage struct {
	UncoveredHosts []string `json:"uncoveredHosts"`
	UncoveredIPs   []string `json:"uncoveredIps"`
}

// Check tests values against the policy. hosts and ips are the real
// inventory values of the fields labelled host and ip.
func (r Redaction) Check(hosts, ips []string) Coverage {
	rd, err := NewRedactor(r.Rules())
	if err != nil {
		return Coverage{UncoveredHosts: hosts, UncoveredIPs: ips}
	}
	var c Coverage
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.Contains(h, ".") && !rd.matchDomain(h) {
			c.UncoveredHosts = append(c.UncoveredHosts, h)
		}
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) != nil && !rd.matchIP(ip) {
			c.UncoveredIPs = append(c.UncoveredIPs, ip)
		}
	}
	return c
}
