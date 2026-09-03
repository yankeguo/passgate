package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Gate implements the PassKey gate: registration on first visit, assertion
// afterwards, and a JWT session cookie on success.
type Gate struct {
	store      *Store
	sessionTTL time.Duration
	origin     string // optional pinned origin (PASSGATE_ORIGIN)

	mu        sync.Mutex
	webauthns map[string]*webauthn.WebAuthn // origin → RP instance
	sessions  map[string]*challengeSession  // challenge → in-flight ceremony
}

type challengeSession struct {
	data    webauthn.SessionData
	expires time.Time
}

func NewGate(store *Store, sessionTTL time.Duration, origin string) *Gate {
	return &Gate{
		store:      store,
		sessionTTL: sessionTTL,
		origin:     origin,
		webauthns:  make(map[string]*webauthn.WebAuthn),
		sessions:   make(map[string]*challengeSession),
	}
}

// requestOrigin derives the externally visible origin of the request,
// honoring X-Forwarded-Proto when deployed behind a TLS-terminating proxy.
func requestOrigin(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host
}

func (g *Gate) webauthnFor(origin string) (*webauthn.WebAuthn, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w, ok := g.webauthns[origin]; ok {
		return w, nil
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Passgate",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, err
	}
	g.webauthns[origin] = w
	return w, nil
}

func (g *Gate) rp(r *http.Request) (*webauthn.WebAuthn, error) {
	if g.origin != "" {
		return g.webauthnFor(g.origin)
	}
	return g.webauthnFor(requestOrigin(r))
}

func (g *Gate) isSecure(r *http.Request) bool {
	if g.origin != "" {
		return len(g.origin) >= 6 && g.origin[:6] == "https:"
	}
	return requestOrigin(r)[:6] == "https:"
}

func (g *Gate) stash(data webauthn.SessionData) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, s := range g.sessions {
		if now.After(s.expires) {
			delete(g.sessions, k)
		}
	}
	g.sessions[data.Challenge] = &challengeSession{data: data, expires: now.Add(5 * time.Minute)}
}

func (g *Gate) take(challenge string) (webauthn.SessionData, bool) {
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
	})
}

// sanitizeNext keeps only site-local redirect targets.
func sanitizeNext(next string) string {
	if len(next) > 1 && next[0] == '/' && next[1] != '/' {
		return next
	}
	return "/"
}

func (g *Gate) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() != nil {
		writeError(w, http.StatusConflict, "a passkey is already registered")
		return
	}
	rp, err := g.rp(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	creation, session, err := rp.BeginRegistration(&user{store: g.store})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.stash(*session)
	writeJSON(w, creation)
}

func (g *Gate) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() != nil {
		writeError(w, http.StatusConflict, "a passkey is already registered")
		return
	}
	rp, err := g.rp(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, ok := g.take(parsed.Response.CollectedClientData.Challenge)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown or expired ceremony")
		return
	}
	cred, err := rp.CreateCredential(&user{store: g.store}, session, parsed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := g.store.SetCredential(cred); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.issueSession(w, r)
}

func (g *Gate) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() == nil {
		writeError(w, http.StatusConflict, "no passkey registered yet")
		return
	}
	rp, err := g.rp(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assertion, session, err := rp.BeginLogin(&user{store: g.store})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	g.stash(*session)
	writeJSON(w, assertion)
}

func (g *Gate) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if g.store.Credential() == nil {
		writeError(w, http.StatusConflict, "no passkey registered yet")
		return
	}
	rp, err := g.rp(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, ok := g.take(parsed.Response.CollectedClientData.Challenge)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown or expired ceremony")
		return
	}
	if _, err := rp.ValidateLogin(&user{store: g.store}, session, parsed); err != nil {
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
