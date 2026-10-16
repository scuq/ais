package backend

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// ProxyHandler forwards everything to the unix socket. It runs inside the
// backend sidecar container on the internal network, so run containers
// have a fixed IP to talk to and the daemon never listens on a container
// network itself.
func ProxyHandler(socket string) http.Handler {
	target, _ := url.Parse("http://ais-backend")
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout: 60 * time.Second,
	}
	rp.FlushInterval = -1 // stream SSE responses immediately
	return rp
}
