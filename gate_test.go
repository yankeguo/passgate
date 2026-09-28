package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func newTestGate(t *testing.T, store *Store, origin, title string) *Gate {
	t.Helper()
	g, err := NewGate(store, time.Hour, origin, title)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

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

	if newTestGate(t, store, "", "").isSecure(r) != true {
		t.Fatal("forwarded https should be secure")
	}
	if newTestGate(t, store, "https://gate.example.com", "").isSecure(r) != true {
		t.Fatal("pinned https origin should be secure")
	}
	if newTestGate(t, store, "http://gate.example.com", "").isSecure(r) != false {
		t.Fatal("pinned http origin should not be secure")
	}
}

func TestChallengeLifecycle(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := newTestGate(t, store, "", "")

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

func TestFormatAndMatchSetupKey(t *testing.T) {
	key := "a1b2c3d4e5f67890a1b2c3d4e5f67890"
	formatted := formatSetupKey(key)
	if formatted != "a1b2-c3d4-e5f6-7890-a1b2-c3d4-e5f6-7890" {
		t.Fatalf("formatSetupKey = %q", formatted)
	}
	if !setupKeysEqual("A1B2-C3D4-E5F6-7890-A1B2-C3D4-E5F6-7890", key) {
		t.Fatal("hyphenated uppercase key should match")
	}
	if !setupKeysEqual("  a1b2 c3d4 e5f6 7890 a1b2 c3d4 e5f6 7890  ", key) {
		t.Fatal("spaced key should match")
	}
	if setupKeysEqual("nope", key) || setupKeysEqual("", key) {
		t.Fatal("wrong or empty key should not match")
	}
	if setupKeysEqual("", "") {
		t.Fatal("empty keys must not compare equal")
	}
}

func TestSetupKeyIsMemoryOnlyUntilRegistered(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := newTestGate(t, store, "", "")
	key := g.SetupKey()
	if len(key) != setupKeyBytes*2 {
		t.Fatalf("setup key length = %d, want %d hex chars", len(key), setupKeyBytes*2)
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), key) || strings.Contains(string(data), formatSetupKey(key)) {
		t.Fatal("setup key must not be written to state.json")
	}

	if err := store.SetCredential(&webauthn.Credential{ID: []byte("cred-id")}); err != nil {
		t.Fatal(err)
	}
	registered := newTestGate(t, store, "", "")
	if registered.SetupKey() != "" {
		t.Fatal("a registered store must not arm a setup key")
	}
}

func TestRegisterRequiresSetupKey(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Pin a hostname: the WebAuthn RP ID rejects an IP, and httptest serves on 127.0.0.1.
	g := newTestGate(t, store, "http://localhost", "")
	srv := httptest.NewServer(NewServer(g, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Handler())
	t.Cleanup(srv.Close)

	beginURL := srv.URL + "/__passgate/api/register/begin"
	finishURL := srv.URL + "/__passgate/api/register/finish"

	assertStatus := func(method, url, key string, body io.Reader, want int) string {
		t.Helper()
		req, err := http.NewRequest(method, url, body)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.Header.Set(setupKeyHeader, key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		payload, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s key=%q: status = %d, want %d, body %s", method, url, key, resp.StatusCode, want, payload)
		}
		return string(payload)
	}

	body := assertStatus(http.MethodPost, beginURL, "", nil, http.StatusUnauthorized)
	if !strings.Contains(body, "invalid setup key") {
		t.Fatalf("body = %s", body)
	}
	assertStatus(http.MethodPost, beginURL, "wrong-key", nil, http.StatusUnauthorized)
	longKey := strings.Repeat("a", 129)
	assertStatus(http.MethodPost, beginURL, longKey, nil, http.StatusUnauthorized)
	if n := len(g.sessions); n != 0 {
		t.Fatalf("rejected attempts stored %d challenges", n)
	}

	body = assertStatus(http.MethodPost, beginURL, formatSetupKey(g.SetupKey()), nil, http.StatusOK)
	var creation struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &creation); err != nil || len(creation.PublicKey) == 0 {
		t.Fatalf("begin body = %s", body)
	}
	if n := len(g.sessions); n != 1 {
		t.Fatalf("successful begin stored %d challenges, want 1", n)
	}

	assertStatus(http.MethodPost, finishURL, "", strings.NewReader(`{}`), http.StatusUnauthorized)
	assertStatus(http.MethodPost, finishURL, "wrong-key", strings.NewReader(`{}`), http.StatusUnauthorized)
	// The key is accepted; the body is not a WebAuthn attestation.
	assertStatus(http.MethodPost, finishURL, g.SetupKey(), strings.NewReader(`{}`), http.StatusBadRequest)
}

func TestGatePageShowsSetupKeyOnlyBeforeRegistration(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := newTestGate(t, store, "", "")

	rec := httptest.NewRecorder()
	g.handlePage(rec, httptest.NewRequest(http.MethodGet, "/__passgate/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `id="setup-key"`) {
		t.Fatal("unregistered gate page should ask for the setup key")
	}
	if strings.Contains(body, g.SetupKey()) || strings.Contains(body, formatSetupKey(g.SetupKey())) {
		t.Fatal("gate page must not embed the setup key")
	}

	if err := store.SetCredential(&webauthn.Credential{ID: []byte("cred-id")}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	g.handlePage(rec, httptest.NewRequest(http.MethodGet, "/__passgate/", nil))
	body = rec.Body.String()
	if strings.Contains(body, `id="setup-key"`) {
		t.Fatal("registered gate page should not ask for the setup key")
	}
	if !strings.Contains(body, "Sign in with PassKey") {
		t.Fatal("registered gate page should offer sign-in")
	}
}
