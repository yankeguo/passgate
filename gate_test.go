package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestSanitizeNext(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/dashboard", "/dashboard"},
		{"/a/b?x=1", "/a/b?x=1"},
		{"", "/"},
		{"/", "/"},
		{"https://evil.com", "/"},
		{"//evil.com", "/"},
		{`/\evil.com`, "/"},
		{"javascript:alert(1)", "/"},
	}
	for _, tt := range tests {
		if got := sanitizeNext(tt.in); got != tt.want {
			t.Errorf("sanitizeNext(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRequestOrigin(t *testing.T) {
	r := httptest.NewRequest("GET", "http://gate.example/", nil)
	if got := requestOrigin(r); got != "http://gate.example" {
		t.Fatalf("origin = %q", got)
	}

	r = httptest.NewRequest("GET", "http://gate.example/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := requestOrigin(r); got != "https://gate.example" {
		t.Fatalf("origin = %q", got)
	}

	// Anything beyond plain http/https must be ignored.
	r = httptest.NewRequest("GET", "http://gate.example/", nil)
	r.Header.Set("X-Forwarded-Proto", "httpsx")
	if got := requestOrigin(r); got != "http://gate.example" {
		t.Fatalf("origin = %q", got)
	}
}

func TestIsSecure(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://gate.example/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")

	if NewGate(store, time.Hour, "").isSecure(r) != true {
		t.Fatal("forwarded https should be secure")
	}
	if NewGate(store, time.Hour, "https://gate.example.com").isSecure(r) != true {
		t.Fatal("pinned https origin should be secure")
	}
	if NewGate(store, time.Hour, "http://gate.example.com").isSecure(r) != false {
		t.Fatal("pinned http origin should not be secure")
	}
}

func TestChallengeLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := NewGate(store, time.Hour, "")

	data := webauthn.SessionData{Challenge: "c1"}
	g.saveChallenge(data)
	if _, ok := g.takeChallenge("c1"); !ok {
		t.Fatal("stashed challenge should be retrievable")
	}
	if _, ok := g.takeChallenge("c1"); ok {
		t.Fatal("a challenge must complete at most once")
	}
	if _, ok := g.takeChallenge("unknown"); ok {
		t.Fatal("unknown challenge should not verify")
	}

	g.mu.Lock()
	g.sessions["expired"] = &challengeSession{data: webauthn.SessionData{Challenge: "expired"}, expires: time.Now().Add(-time.Minute)}
	g.mu.Unlock()
	if _, ok := g.takeChallenge("expired"); ok {
		t.Fatal("expired challenge should not verify")
	}
}
