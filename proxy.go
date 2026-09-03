package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// newProxy builds a reverse proxy to the upstream service. The Host header is
// rewritten to the upstream's so virtual-host based services behave; the
// client's address is appended to X-Forwarded-For by the proxy itself.
func newProxy(upstream *url.URL) http.Handler {
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = upstream.Scheme
			pr.Out.URL.Host = upstream.Host
			pr.Out.Host = upstream.Host
		},
	}
	return p
}
