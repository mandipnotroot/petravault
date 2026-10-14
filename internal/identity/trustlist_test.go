// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"errors"
	"testing"

	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
)

func mustTrustListIdentities(t *testing.T) (*identity.Store, *identity.TrustStore, *identity.PrivateIdentity, *identity.Identity, *identity.Identity) {
	t.Helper()
	store, _ := newTestStore(t)
	alice, err := store.Create("alice-trustlist", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	alicePriv, err := store.LoadPrivate(alice.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Create("bob-trustlist", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	trust := newTestTrust(t)
	if err := trust.Add(alice); err != nil {
		t.Fatal(err)
	}
	if err := trust.Add(bob); err != nil {
		t.Fatal(err)
	}
	return store, trust, alicePriv, alice, bob
}

func TestTrustListPublishRecoverRoundTrip(t *testing.T) {
	t.Parallel()

	_, trust, alicePriv, alice, bob := mustTrustListIdentities(t)
	bobEnv, err := identity.SignRevocation(alicePriv, bob.Fingerprint, "left", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AddRevocation(bob.Fingerprint, bobEnv); err != nil {
		t.Fatal(err)
	}

	env, err := identity.PublishTrustList(alicePriv, trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, []byte("alice-trustlist")) || bytes.Contains(env, []byte("bob-trustlist")) {
		t.Fatal("published envelope leaks member names in plaintext")
	}

	fresh := newTestTrust(t)
	summary, err := identity.RecoverTrustList(env, alicePriv, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Trusted != 2 || summary.Revoked != 1 {
		t.Fatalf("summary = %+v, want 2 trusted and 1 revoked", summary)
	}
	if trusted, err := fresh.IsTrusted(alice.Fingerprint); err != nil || !trusted {
		t.Fatal("alice is not trusted after recovery")
	}
	if trusted, err := fresh.IsTrusted(bob.Fingerprint); err != nil || trusted {
		t.Fatal("bob is trusted after recovery, want revoked")
	}
	if revoked, err := fresh.IsRevoked(bob.Fingerprint); err != nil || !revoked {
		t.Fatal("bob revocation missing after recovery")
	}
}

func TestTrustListRecoverRejectsWrongOwner(t *testing.T) {
	t.Parallel()

	_, trust, alicePriv, _, _ := mustTrustListIdentities(t)
	env, err := identity.PublishTrustList(alicePriv, trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, _ := newTestStore(t)
	other, err := otherStore.Create("mallory", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := otherStore.LoadPrivate(other.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := newTestTrust(t)
	// Another owner's key: the signature fails.
	if _, err := identity.RecoverTrustList(env, otherPriv, fresh); err == nil {
		t.Fatal("recovery accepted a foreign key")
	} else if !errors.Is(err, pverrors.ErrBadSignature) {
		t.Fatalf("err = %v, want signature failure", err)
	}
}

func TestTrustListRecoverRejectsTampering(t *testing.T) {
	t.Parallel()

	_, trust, alicePriv, _, _ := mustTrustListIdentities(t)
	env, err := identity.PublishTrustList(alicePriv, trust, testTime)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(env)
	tampered[len(tampered)-1] ^= 0x01
	fresh := newTestTrust(t)
	if _, err := identity.RecoverTrustList(tampered, alicePriv, fresh); err == nil {
		t.Fatal("recovery accepted a tampered envelope")
	}
}

func TestTrustListKeyRoundTrip(t *testing.T) {
	t.Parallel()

	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	key := identity.TrustListKey(id.Fingerprint)
	fp, err := identity.ParseTrustListKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !fp.Equal(id.Fingerprint) {
		t.Fatal("trust-list key round trip mismatch")
	}
	if _, err := identity.ParseTrustListKey("keys/" + id.Fingerprint.String() + ".slot"); err == nil {
		t.Fatal("trust-list key parser accepted a slot key")
	}
}
