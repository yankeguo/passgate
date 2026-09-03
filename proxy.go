package main

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// newProxy builds a reverse proxy to the upstream service. The Host header is
// rewritten to the upstream's so virtual-host based services behave; the
// client's address is appended to X-Forwarded-For by the proxy itself.
//
// The proxy is fully transparent: no timeouts and no concurrency/connection
// limits are imposed anywhere — every connection and request is handed to the
// upstream as-is, and slow or long-lived traffic (SSE, WebSocket, big
// uploads) is entirely a matter between the client and the upstream.
func newProxy(upstream *url.URL) http.Handler {
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			pr.Out.Host = upstream.Host
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   0, // no connect timeout
				KeepAlive: -1, // disable keep-alive probes; dead peers surface on their own
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          1 << 30, // effectively unlimited idle pool
			MaxIdleConnsPerHost:   1 << 30, // default would cap reuse at 2 per host
			MaxConnsPerHost:       0,       // no concurrency cap
			IdleConnTimeout:       0,       // idle connections never expire
			TLSHandshakeTimeout:   0,
			ExpectContinueTimeout: 0,
		},
		// Flush every write immediately so streaming responses reach the
		// client with no proxy-side buffering delay.
		FlushInterval: -1,
	}
	return p
}
