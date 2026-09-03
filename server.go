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
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /passgate/{$}", s.gate.handlePage)
	mux.HandleFunc("POST /passgate/api/register/begin", s.gate.handleRegisterBegin)
	mux.HandleFunc("POST /passgate/api/register/finish", s.gate.handleRegisterFinish)
	mux.HandleFunc("POST /passgate/api/login/begin", s.gate.handleLoginBegin)
	mux.HandleFunc("POST /passgate/api/login/finish", s.gate.handleLoginFinish)
	mux.Handle("GET /static/", staticHandler())
	mux.Handle("/", s.withAuth(s.proxy))
	return s.withSecurityHeaders(mux)
}

// withAuth forwards requests carrying a valid session cookie to the upstream
// service; everything else is sent to the gate page.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.gate.authed(r) {
			http.Redirect(w, r, "/passgate/?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
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
