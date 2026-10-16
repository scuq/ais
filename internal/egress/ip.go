// Package egress owns the network topology that keeps run containers from
// reaching anything but an allowlisted set of domains: an internal network
// with no route out, a squid sidecar at a fixed address on it, and the
// allowlist the sidecar enforces.
package egress

import (
	"fmt"
	"net"
)

// Fixed host offsets inside the internal subnet. Sidecars get static IPs so
// nothing inside the internal network has to resolve names.
const (
	ProxyOffset   = 2
	BackendOffset = 4
)

// Network names.
const (
	InternalNetwork = "ais-internal"
	EgressNetwork   = "ais-egress"
)

// Sidecar container names.
const (
	ProxyContainer   = "ais-proxy"
	BackendContainer = "ais-backend"
)

// HostIP returns the address at offset inside the subnet.
func HostIP(subnet string, offset int) (string, error) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("subnet %q: %w", subnet, err)
	}
	ip := n.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("subnet %q: IPv4 only", subnet)
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	out[3] += byte(offset)
	if !n.Contains(out) {
		return "", fmt.Errorf("subnet %q too small for offset %d", subnet, offset)
	}
	return out.String(), nil
}

// ProxyIP is the squid sidecar's address.
func ProxyIP(subnet string) (string, error) { return HostIP(subnet, ProxyOffset) }

// BackendIP is the backend sidecar's address.
func BackendIP(subnet string) (string, error) { return HostIP(subnet, BackendOffset) }

// ProxyURL is what HTTP(S)_PROXY is set to inside run containers.
func ProxyURL(subnet string, port int) (string, error) {
	ip, err := ProxyIP(subnet)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s:%d", ip, port), nil
}
