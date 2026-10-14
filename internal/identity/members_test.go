// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"errors"
	"testing"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
)

func mustMembersSetup(t *testing.T) (crypto.SecretKey, *identity.Store, *identity.TrustStore, *identity.PrivateIdentity, *identity.Identity, *identity.Identity) {
	t.Helper()
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	store, _ := newTestStore(t)
	alice, err := store.Create("alice-members", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	alicePriv, err := store.LoadPrivate(alice.Fingerprint, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Create("bob-members", []byte("password"), testTime)
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
	return master, store, trust, alicePriv, alice, bob
}

func membersDataKey(t *testing.T, master crypto.SecretKey) crypto.SecretKey {
	t.Helper()
	return master.DeriveSubkeys().Data
}

func membersLookup(t *testing.T, ids ...*identity.Identity) func(string) ([]byte, error) {
	t.Helper()
	m := make(map[string][]byte, len(ids))
	for _, id := range ids {
		m[id.Fingerprint.String()] = id.SignPublic
	}
	return func(publisher string) ([]byte, error) {
		pub, ok := m[publisher]
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("unknown publisher"))
		}
		return pub, nil
	}
}

func TestMembersPublishAdoptRoundTrip(t *testing.T) {
	t.Parallel()

	master, _, trust, alicePriv, alice, bob := mustMembersSetup(t)
	dataKey := membersDataKey(t, master)
	env, err := identity.PublishMembers(alicePriv, trust, dataKey, "repo-1", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, []byte("alice-members")) || bytes.Contains(env, []byte("bob-members")) {
		t.Fatal("published roster leaks member names in plaintext")
	}

	fresh := newTestTrust(t)
	if err := fresh.Add(alice); err != nil {
		t.Fatal(err)
	}
	summary, err := identity.AdoptMembers(env, dataKey, "repo-1", fresh, membersLookup(t, alice))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Adopted != 1 {
		t.Fatalf("adopted = %d, want 1 (bob; alice already trusted)", summary.Adopted)
	}
	if trusted, err := fresh.IsTrusted(bob.Fingerprint); err != nil || !trusted {
		t.Fatal("bob is not trusted after adopt")
	}
}

func TestMembersPublishExcludesRevoked(t *testing.T) {
	t.Parallel()

	master, _, trust, alicePriv, alice, _ := mustMembersSetup(t)
	malloryStore, _ := newTestStore(t)
	mallory, err := malloryStore.Create("mallory-members", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Add(mallory); err != nil {
		t.Fatal(err)
	}
	malloryEnv, err := identity.SignRevocation(alicePriv, mallory.Fingerprint, "out", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AddRevocation(mallory.Fingerprint, malloryEnv); err != nil {
		t.Fatal(err)
	}
	dataKey := membersDataKey(t, master)
	env, err := identity.PublishMembers(alicePriv, trust, dataKey, "repo-1", testTime)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newTestTrust(t)
	if err := fresh.Add(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.AdoptMembers(env, dataKey, "repo-1", fresh, membersLookup(t, alice)); err != nil {
		t.Fatal(err)
	}
	if trusted, err := fresh.IsTrusted(mallory.Fingerprint); err != nil || trusted {
		t.Fatal("revoked mallory was adopted from the roster")
	}
}

func TestMembersAdoptRejectsUntrustedPublisher(t *testing.T) {
	t.Parallel()

	master, _, trust, alicePriv, alice, _ := mustMembersSetup(t)
	dataKey := membersDataKey(t, master)
	env, err := identity.PublishMembers(alicePriv, trust, dataKey, "repo-1", testTime)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newTestTrust(t)
	if _, err := identity.AdoptMembers(env, dataKey, "repo-1", fresh, membersLookup(t, alice)); err == nil {
		t.Fatal("adopt accepted an untrusted publisher")
	} else if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("err = %v, want untrusted signer", err)
	}
}

func TestMembersAdoptRejectsWrongKeyAndRepo(t *testing.T) {
	t.Parallel()

	master, _, trust, alicePriv, alice, _ := mustMembersSetup(t)
	dataKey := membersDataKey(t, master)
	env, err := identity.PublishMembers(alicePriv, trust, dataKey, "repo-1", testTime)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newTestTrust(t)
	if err := fresh.Add(alice); err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.AdoptMembers(env, membersDataKey(t, other), "repo-1", fresh, membersLookup(t, alice)); err == nil {
		t.Fatal("adopt opened the seal with the wrong key")
	} else if !errors.Is(err, pverrors.ErrAuthFailed) {
		t.Fatalf("err = %v, want authentication failure", err)
	}
	if _, err := identity.AdoptMembers(env, dataKey, "repo-2", fresh, membersLookup(t, alice)); err == nil {
		t.Fatal("adopt opened the seal for another repository")
	} else if !errors.Is(err, pverrors.ErrAuthFailed) {
		t.Fatalf("err = %v, want authentication failure", err)
	}
	tampered := bytes.Clone(env)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := identity.AdoptMembers(tampered, dataKey, "repo-1", fresh, membersLookup(t, alice)); err == nil {
		t.Fatal("adopt accepted a tampered envelope")
	}
}
