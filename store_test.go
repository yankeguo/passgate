package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestOpenStoreGeneratesSecret(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Secret()) != 32 {
		t.Fatalf("secret length = %d, want 32", len(s.Secret()))
	}
	if s.Credential() != nil {
		t.Fatal("fresh store should have no credential")
	}

	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json mode = %o, want 600", info.Mode().Perm())
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred := &webauthn.Credential{ID: []byte("cred-id"), PublicKey: []byte("pubkey")}
	if err := s.SetCredential(cred); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(s2.Secret()) != string(s.Secret()) {
		t.Fatal("secret did not survive reload")
	}
	got := s2.Credential()
	if got == nil || string(got.ID) != "cred-id" || string(got.PublicKey) != "pubkey" {
		t.Fatalf("credential did not survive reload: %+v", got)
	}
}

func TestUserCredentials(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	u := &user{store: s}
	if n := len(u.WebAuthnCredentials()); n != 0 {
		t.Fatalf("credentials = %d, want 0", n)
	}
	if err := s.SetCredential(&webauthn.Credential{ID: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if n := len(u.WebAuthnCredentials()); n != 1 {
		t.Fatalf("credentials = %d, want 1", n)
	}
}
