package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Store persists the single-user gate state (JWT signing secret plus the one
// registered PassKey credential) as a JSON file in the data directory.
type Store struct {
	path string

	mu         sync.Mutex
	secret     []byte
	credential *webauthn.Credential
}

type storeFile struct {
	Secret     []byte              `json:"secret"`
	Credential *webauthn.Credential `json:"credential,omitempty"`
}

// OpenStore loads (or creates) the state file in dir. On first run a random
// 32-byte session signing secret is generated and persisted.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}

	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.secret = make([]byte, 32)
		if _, err := rand.Read(s.secret); err != nil {
			return nil, err
		}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		var f storeFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", s.path, err)
		}
		if len(f.Secret) < 16 {
			return nil, fmt.Errorf("%s: secret missing or too short", s.path)
		}
		s.secret = f.Secret
		s.credential = f.Credential
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(storeFile{Secret: s.secret, Credential: s.credential}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Secret returns the session (JWT) signing key.
func (s *Store) Secret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret
}

// Credential returns the registered PassKey credential, or nil when none has
// been registered yet (first-run state).
func (s *Store) Credential() *webauthn.Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credential
}

// SetCredential registers the PassKey credential and persists it.
func (s *Store) SetCredential(c *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credential = c
	return s.saveLocked()
}

// user adapts the store to webauthn.User for the single gate owner.
type user struct {
	store *Store
}

var userHandle = []byte("passgate-owner")

func (u *user) WebAuthnID() []byte          { return userHandle }
func (u *user) WebAuthnName() string        { return "owner" }
func (u *user) WebAuthnDisplayName() string { return "Owner" }

func (u *user) WebAuthnCredentials() []webauthn.Credential {
	if c := u.store.Credential(); c != nil {
		return []webauthn.Credential{*c}
	}
	return nil
}
