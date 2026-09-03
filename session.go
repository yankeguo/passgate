package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const sessionCookieName = "passgate_session"

// signSession issues an HS256 JWT marking the gate owner as authenticated.
func signSession(secret []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   "owner",
		Issuer:    "passgate",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// verifySession reports whether token is a valid, unexpired session JWT.
func verifySession(secret []byte, token string) bool {
	_, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithIssuer("passgate"), jwt.WithSubject("owner"))
	return err == nil
}

// setSessionCookie writes the session cookie. secure mirrors the request
// scheme so cookies are only marked Secure when served over HTTPS.
func setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func sessionFromRequest(secret []byte, r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	return err == nil && verifySession(secret, c.Value)
}
