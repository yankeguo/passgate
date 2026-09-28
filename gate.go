package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// defaultTitle is the gate page title when none is configured.
const defaultTitle = "passgate"

// setupKeyHeader carries the in-memory bootstrap key on first registration.
// A custom header cannot be set by a cross-origin form post.
const setupKeyHeader = "X-Passgate-Setup-Key"

// setupKeyBytes is the entropy of the bootstrap key (128 bits).
const setupKeyBytes = 16

// Gate implements the PassKey gate: registration on first visit, assertion
// afterwards, and a JWT session cookie on success.
//
// Until a passkey exists, startup also keeps a random setup key in memory.
// Registration is refused without it, so a reachable gate cannot be claimed
// by whoever loads the page first.
type Gate struct {
	store      *Store
	sessionTTL time.Duration
	origin     string // optional pinned origin (PASSGATE_ORIGIN)
	title      string // page title (browser tab and header)

	mu       sync.Mutex
	setupKey string                       // canonical hex; empty once a passkey exists
	sessions map[string]*challengeSession // challenge → in-flight ceremony
}

// challengeTTL bounds how long a begun WebAuthn ceremony stays completable.
const challengeTTL = 5 * time.Minute

type challengeSession struct {
	data    webauthn.SessionData
	expires time.Time
}

func NewGate(store *Store, sessionTTL time.Duration, origin, title string) (*Gate, error) {
	if title == "" {
		title = defaultTitle
	}
	g := &Gate{
		store:      store,
		sessionTTL: sessionTTL,
		origin:     origin,
		title:      title,
		sessions:   make(map[string]*challengeSession),
	}
	if store.Credential() == nil {
		key, err := newSetupKey()
		if err != nil {
			return nil, fmt.Errorf("generate setup key: %w", err)
		}
		g.setupKey = key
	}
	return g, nil
}

// SetupKey returns the canonical (unhyphenated, lowercase hex) bootstrap key,
// or "" when a passkey is already registered. The key is never persisted.
func (g *Gate) SetupKey() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.setupKey
}

func (g *Gate) clearSetupKey() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.setupKey = ""
}

// newSetupKey returns 128 bits of randomness as lowercase hex.
func newSetupKey() (string, error) {
	buf := make([]byte, setupKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// formatSetupKey groups a canonical key as xxxx-xxxx-... for the terminal.
func formatSetupKey(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := i + 4
		if end > len(key) {
			end = len(key)
		}
		b.WriteString(key[i:end])
	}
	return b.String()
}

func normalizeSetupKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

// setupKeysEqual compares a typed key with the canonical one. Digests are
// compared so a length mismatch cannot short-circuit on the secret.
func setupKeysEqual(got, want string) bool {
	if want == "" || strings.TrimSpace(got) == "" {
		return false
	}
	gh := sha256.Sum256([]byte(normalizeSetupKey(got)))
	wh := sha256.Sum256([]byte(normalizeSetupKey(want)))
	return subtle.ConstantTimeCompare(gh[:], wh[:]) == 1
}

// setupKeyOK reports whether the request presents the in-memory bootstrap key.
func (g *Gate) setupKeyOK(r *http.Request) bool {
	got := r.Header.Get(setupKeyHeader)
	if len(got) > 128 {
		return false
	}
	g.mu.Lock()
	want := g.setupKey
	g.mu.Unlock()
	return setupKeysEqual(got, want)
}

// requestOrigin derives the externally visible origin of the request,
// honoring X-Forwarded-Proto when deployed behind a TLS-terminating proxy.
func requestOrigin(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme != "https" && scheme != "http" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host
}

// webauthnFor builds the RP (relying party) instance for the request's
// origin. webauthn.New is cheap config validation, so instances are created
// per call rather than cached — a cache keyed on the client-controlled Host
// header would grow without bound.
func (g *Gate) webauthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := g.origin
	if origin == "" {
		origin = requestOrigin(r)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Passgate",
		RPOrigins:     []string{origin},
	})
}

func (g *Gate) isSecure(r *http.Request) bool {
	origin := g.origin
	if origin == "" {
		origin = requestOrigin(r)
	}
	return strings.HasPrefix(origin, "https:")
}

// saveChallenge stashes a begun ceremony, sweeping expired ones in passing.
func (g *Gate) saveChallenge(data webauthn.SessionData) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, s := range g.sessions {
		if now.After(s.expires) {
			delete(g.sessions, k)
		}
	}
	g.sessions[data.Challenge] = &challengeSession{data: data, expires: now.Add(challengeTTL)}
}

// takeChallenge consumes a stashed ceremony: each challenge completes once.
func (g *Gate) takeChallenge(challenge string) (webauthn.SessionData, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[challenge]
	if ok {
		delete(g.sessions, challenge)
	}
	if !ok || time.Now().After(s.expires) {
		return webauthn.SessionData{}, false
	}
	return s.data, true
}

// handlePage renders the gate page: registration prompt on first visit,
// sign-in prompt once a credential exists.
func (g *Gate) handlePage(w http.ResponseWriter, r *http.Request) {
	render(w, "gate.html", map[string]any{
		"Registered": g.store.Credential() != nil,
		"Next":       sanitizeNext(r.URL.Query().Get("next")),
		"Title":      g.title,
	})
}

// sanitizeNext keeps only site-local redirect targets. "//evil.com" is
// rejected as protocol-relative; "/\evil.com" is rejected because browsers
// normalize the backslash to a slash, again yielding "//evil.com".
func sanitizeNext(next string) string {
	if len(next) > 1 && next[0] == '/' && next[1] != '/' && next[1] != '\\' {
		return next
	}
	return "/"
}

func (g *Gate) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() != nil {
		writeError(w, http.StatusConflict, "a passkey is already registered")
		return
	}
	if !g.setupKeyOK(r) {
		writeError(w, http.StatusUnauthorized, "invalid setup key")
		return
	}
	rp, err := g.webauthnFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	creation, session, err := rp.BeginRegistration(&owner{store: g.store})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.saveChallenge(*session)
	writeJSON(w, creation)
}

func (g *Gate) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() != nil {
		writeError(w, http.StatusConflict, "a passkey is already registered")
		return
	}
	if !g.setupKeyOK(r) {
		writeError(w, http.StatusUnauthorized, "invalid setup key")
		return
	}
	rp, err := g.webauthnFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, ok := g.takeChallenge(parsed.Response.CollectedClientData.Challenge)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown or expired ceremony")
		return
	}
	cred, err := rp.CreateCredential(&owner{store: g.store}, session, parsed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := g.store.SetCredential(cred); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	g.clearSetupKey()
	g.issueSession(w, r)
}

func (g *Gate) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() == nil {
		writeError(w, http.StatusConflict, "no passkey registered yet")
		return
	}
	rp, err := g.webauthnFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assertion, session, err := rp.BeginLogin(&owner{store: g.store})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.saveChallenge(*session)
	writeJSON(w, assertion)
}

func (g *Gate) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() == nil {
		writeError(w, http.StatusConflict, "no passkey registered yet")
		return
	}
	rp, err := g.webauthnFor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, ok := g.takeChallenge(parsed.Response.CollectedClientData.Challenge)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown or expired ceremony")
		return
	}
	if _, err := rp.ValidateLogin(&owner{store: g.store}, session, parsed); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	g.issueSession(w, r)
}

// issueSession signs the JWT, sets the cookie, and answers the finish calls.
func (g *Gate) issueSession(w http.ResponseWriter, r *http.Request) {
	token, err := signSession(g.store.Secret(), g.sessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	setSessionCookie(w, token, g.sessionTTL, g.isSecure(r))
	writeJSON(w, map[string]any{"ok": true})
}

// authed reports whether the request carries a valid session cookie.
func (g *Gate) authed(r *http.Request) bool {
	return sessionFromRequest(g.store.Secret(), r)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println("json:", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
