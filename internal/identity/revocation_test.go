// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"testing"

	"petravault/internal/crypto"
	"petravault/internal/identity"
)

func TestSelfRevocation(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SignRevocation(priv, id.Fingerprint, "lost laptop", testTime)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := identity.VerifyRevocation(env, id.SignPublic)
	if err != nil {
		t.Fatal(err)
	}
	if !rev.Fingerprint.Equal(id.Fingerprint) || !rev.Signer.Equal(id.Fingerprint) {
		t.Fatal("self-revocation fields mismatch")
	}
	if rev.Reason != "lost laptop" {
		t.Fatalf("reason = %q, want lost laptop", rev.Reason)
	}
}

func TestRevocationTamperedSignatureFails(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SignRevocation(priv, id.Fingerprint, "reason", testTime)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(env)
	if len(tampered) > 20 {
		if tampered[20] == 'A' {
			tampered[20] = 'B'
		} else {
			tampered[20] = 'A'
		}
	}
	if _, err := identity.VerifyRevocation(tampered, id.SignPublic); err == nil {
		t.Fatal("VerifyRevocation accepted a tampered envelope")
	}
}

func TestRevocationWrongContextKeyFails(t *testing.T) {
	// A manifest signature must never verify as a revocation: contexts
	// separate purposes (DESIGN.md §4.3).
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("manifest payload")
	sig, err := priv.Sign(crypto.ContextManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(id.SignPublic, crypto.ContextRevocation, msg, sig); err == nil {
		t.Fatal("revocation context accepted a manifest signature")
	}
}

func TestSignRevocationRequiresReason(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.SignRevocation(priv, id.Fingerprint, "", testTime); err == nil {
		t.Fatal("SignRevocation accepted an empty reason")
	}
}

func TestRevocationRejectsUnknownFields(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SignRevocation(priv, id.Fingerprint, "reason", testTime)
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(env, []byte(`"payload":"`), []byte(`"extra":true,"payload":"`), 1)
	if _, err := identity.VerifyRevocation(withExtra, id.SignPublic); err == nil {
		t.Fatal("VerifyRevocation accepted an unknown envelope field")
	}
}
