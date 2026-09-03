package main

import (
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Server struct {
	gate  *Gate
	proxy http.Handler
}

func NewServer(gate *Gate, proxy http.Handler) *Server {
	return &Server{gate: gate, proxy: proxy}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Everything passgate owns lives under /__passgate/ so no common path
	// (/static, /healthz, ...) is taken away from the upstream.
	// Security headers (CSP, no-store, ...) apply ONLY to this surface;
	// proxied responses are passed through untouched — the upstream owns
	// its headers.
	mux.Handle("GET /__passgate/healthz", s.withSecurityHeaders(http.HandlerFunc(s.handleHealthz)))
	mux.Handle("GET /__passgate/{$}", s.withSecurityHeaders(http.HandlerFunc(s.gate.handlePage)))
	mux.Handle("POST /__passgate/api/register/begin", s.withSecurityHeaders(http.HandlerFunc(s.gate.handleRegisterBegin)))
	mux.Handle("POST /__passgate/api/register/finish", s.withSecurityHeaders(http.HandlerFunc(s.gate.handleRegisterFinish)))
	mux.Handle("POST /__passgate/api/login/begin", s.withSecurityHeaders(http.HandlerFunc(s.gate.handleLoginBegin)))
	mux.Handle("POST /__passgate/api/login/finish", s.withSecurityHeaders(http.HandlerFunc(s.gate.handleLoginFinish)))
	mux.Handle("GET /__passgate/static/", s.withSecurityHeaders(staticHandler()))
	mux.Handle("/", s.withAuth(s.proxy))
	return mux
}

// withAuth forwards requests carrying a valid session cookie to the upstream
// service; everything else is sent to the gate page.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.gate.authed(r) {
			http.Redirect(w, r, "/__passgate/?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'none'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"connect-src 'self'",
			"form-action 'self'",
			"base-uri 'none'",
			"frame-ancestors 'none'",
		}, "; "))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK"))
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := webTmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Println("template:", err)
	}
}
