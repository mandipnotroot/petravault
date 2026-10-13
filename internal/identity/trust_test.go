// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"path/filepath"
	"testing"

	"petravault/internal/identity"
)

func newTestTrust(t *testing.T) *identity.TrustStore {
	t.Helper()
	return identity.NewTrustStore(filepath.Join(t.TempDir(), "trust"))
}

func TestTrustAddListRemove(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	trust := newTestTrust(t)
	if err := trust.Add(id); err != nil {
		t.Fatal(err)
	}
	trusted, err := trust.IsTrusted(id.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("added identity is not trusted")
	}
	listed, err := trust.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].Fingerprint.Equal(id.Fingerprint) {
		t.Fatal("trusted list mismatch")
	}
	if err := trust.Remove(id.Fingerprint); err != nil {
		t.Fatal(err)
	}
	trusted, err = trust.IsTrusted(id.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("removed identity is still trusted")
	}
}

func TestTrustRejectsFingerprintMismatch(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	otherStore, _ := newTestStore(t)
	other, err := otherStore.Create("mallory", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	// Present Mallory's keys under Alice's fingerprint.
	forged := *other
	forged.Fingerprint = id.Fingerprint
	trust := newTestTrust(t)
	if err := trust.Add(&forged); err == nil {
		t.Fatal("trust Add accepted a fingerprint mismatch (repository copy attack)")
	}
	trusted, err := trust.IsTrusted(id.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("forged key became trusted")
	}
}

func TestTrustRevocationDisqualifies(t *testing.T) {
	store, _ := newTestStore(t)
	alice, err := store.Create("alice", []byte("pw-alice"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Create("bob", []byte("pw-bob"), testTime)
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
	alicePriv, err := store.LoadPrivate(alice.Fingerprint, []byte("pw-alice"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SignRevocation(alicePriv, bob.Fingerprint, "key compromised", testTime)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := identity.VerifyRevocation(env, alice.SignPublic)
	if err != nil {
		t.Fatal(err)
	}
	if !rev.Fingerprint.Equal(bob.Fingerprint) || !rev.Signer.Equal(alice.Fingerprint) {
		t.Fatal("revocation fields mismatch")
	}
	if err := trust.AddRevocation(bob.Fingerprint, env); err != nil {
		t.Fatal(err)
	}
	trusted, err := trust.IsTrusted(bob.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("revoked identity is still trusted")
	}
	if _, err := trust.TrustedPublic(bob.Fingerprint); err == nil {
		t.Fatal("TrustedPublic accepted a revoked identity")
	}
	// Revocations only add: removing trust must not clear the revocation.
	if err := trust.Remove(bob.Fingerprint); err != nil {
		t.Fatal(err)
	}
	revoked, err := trust.IsRevoked(bob.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("remove cleared the revocation, want append-only")
	}
}

func TestMultiUserTrust(t *testing.T) {
	// Alice (trusted) verifies; Bob verifies only where trusted;
	// Mallory (untrusted) is rejected everywhere.
	store, _ := newTestStore(t)
	alice, err := store.Create("alice", []byte("pw"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Create("bob", []byte("pw"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	malloryStore, _ := newTestStore(t)
	mallory, err := malloryStore.Create("mallory", []byte("pw"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	clientA := newTestTrust(t)
	if err := clientA.Add(alice); err != nil {
		t.Fatal(err)
	}
	if err := clientA.Add(bob); err != nil {
		t.Fatal(err)
	}
	clientB := newTestTrust(t)
	if err := clientB.Add(alice); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		store *identity.TrustStore
		fp    string
		want  bool
	}{
		{name: "alice trusted on A", store: clientA, fp: "alice", want: true},
		{name: "bob trusted on A", store: clientA, fp: "bob", want: true},
		{name: "alice trusted on B", store: clientB, fp: "alice", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var fp identity.Fingerprint
			switch tt.fp {
			case "alice":
				fp = alice.Fingerprint
			case "bob":
				fp = bob.Fingerprint
			}
			got, err := tt.store.IsTrusted(fp)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("IsTrusted = %v, want %v", got, tt.want)
			}
		})
	}
	if trusted, _ := clientB.IsTrusted(bob.Fingerprint); trusted {
		t.Fatal("bob is trusted on B, want untrusted until added")
	}
	if _, err := clientB.TrustedPublic(mallory.Fingerprint); err == nil {
		t.Fatal("mallory verified on B, want rejection")
	}
	if _, err := clientA.TrustedPublic(mallory.Fingerprint); err == nil {
		t.Fatal("mallory verified on A, want rejection")
	}
}
