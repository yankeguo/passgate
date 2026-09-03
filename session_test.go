package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := signSession(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !verifySession(secret, token) {
		t.Fatal("fresh token should verify")
	}
	if verifySession([]byte("fedcba9876543210fedcba9876543210"), token) {
		t.Fatal("token verified with the wrong secret")
	}
}

func TestSessionExpiry(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := signSession(secret, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if verifySession(secret, token) {
		t.Fatal("expired token should not verify")
	}
}

func TestSessionCookieAndRequest(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := signSession(secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	setSessionCookie(rec, token, time.Hour, true)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("unexpected cookie attributes: %+v", c)
	}

	r := httptest.NewRequest("GET", "/", nil)
	if sessionFromRequest(secret, r) {
		t.Fatal("request without cookie should not authenticate")
	}
	r.AddCookie(c)
	if !sessionFromRequest(secret, r) {
		t.Fatal("request with session cookie should authenticate")
	}
}
