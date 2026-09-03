package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func testServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream:" + r.URL.Path))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gate := NewGate(store, time.Hour, "")
	srv := httptest.NewServer(NewServer(gate, newProxy(upstreamURL)).Handler())
	t.Cleanup(srv.Close)
	return srv, string(store.Secret())
}

func TestUnauthenticatedRedirectsToGate(t *testing.T) {
	srv, _ := testServer(t)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/some/page?x=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/__passgate/?next=%2Fsome%2Fpage%3Fx%3D1" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestGatePageAndHealthz(t *testing.T) {
	srv, _ := testServer(t)

	resp, err := http.Get(srv.URL + "/__passgate/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/__passgate/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gate page status = %d", resp.StatusCode)
	}
	if got := string(body); !contains(got, "Register a PassKey") {
		t.Fatal("first-visit gate page should offer registration")
	}
}

func TestAuthenticatedRequestIsProxied(t *testing.T) {
	srv, secret := testServer(t)

	token, err := signSession([]byte(secret), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest("GET", srv.URL+"/app/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream:/app/dashboard" {
		t.Fatalf("body = %q, want proxied upstream response", body)
	}
	// Proxied responses must be passed through untouched: no passgate
	// security headers (CSP, no-store, ...) may leak onto them.
	for _, h := range []string{"Content-Security-Policy", "Cache-Control", "X-Frame-Options"} {
		if v := resp.Header.Get(h); v != "" {
			t.Fatalf("proxied response carries passgate header %s: %q", h, v)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
