// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package recovery_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"petravault/internal/identity"
	"petravault/internal/recovery"
)

func newRecoveryEnv(t *testing.T) (*identity.Store, *identity.TrustStore) {
	t.Helper()
	root := t.TempDir()
	store := identity.NewStore(filepath.Join(root, "identities"))
	trust := identity.NewTrustStore(filepath.Join(root, "trust"))
	return store, trust
}

func mustRecoveryIdentity(t *testing.T, store *identity.Store, trust *identity.TrustStore, name string) *identity.Identity {
	t.Helper()
	id, err := store.Create(name, []byte("identity-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Add(id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRecoveryImportRejectsWrongPasswords(t *testing.T) {
	store, trust := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	fileBytes, _, err := recovery.Export(store, trust, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	freshStore, freshTrust := newRecoveryEnv(t)
	if _, err := recovery.Import(freshStore, freshTrust, fileBytes, []byte("wrong-password"), []byte("identity-password"), alice.Fingerprint); err == nil {
		t.Fatal("import opened the bundle with the wrong password")
	}
	if _, err := recovery.Import(freshStore, freshTrust, fileBytes, []byte("bundle-password"), []byte("wrong-password"), alice.Fingerprint); err == nil {
		t.Fatal("import verified the private key with the wrong password")
	}
}

func TestRecoveryImportRejectsTampering(t *testing.T) {
	store, trust := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	fileBytes, _, err := recovery.Export(store, trust, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(fileBytes)
	tampered[len(tampered)-1] ^= 0x01
	freshStore, freshTrust := newRecoveryEnv(t)
	if _, err := recovery.Import(freshStore, freshTrust, tampered, []byte("bundle-password"), []byte("identity-password"), alice.Fingerprint); err == nil {
		t.Fatal("import accepted a tampered bundle")
	}
}

func TestRecoveryExportRejectsEmptyPassword(t *testing.T) {
	store, trust := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	if _, _, err := recovery.Export(store, trust, alice.Fingerprint, nil, nil); err == nil {
		t.Fatal("export sealed the bundle with an empty password")
	}
}

func TestRecoveryExportImportRoundTrip(t *testing.T) {
	store, trust := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	bob := mustRecoveryIdentity(t, store, trust, "bob")
	bobEnv, err := identity.SignRevocation(mustLoadPriv(t, store, alice), bob.Fingerprint, "left", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AddRevocation(bob.Fingerprint, bobEnv); err != nil {
		t.Fatal(err)
	}

	fileBytes, summary, err := recovery.Export(store, trust, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Trusted != 2 || summary.Revoked != 1 {
		t.Fatalf("summary = %+v, want 2 trusted, 1 revoked", summary)
	}
	if bytes.Contains(fileBytes, []byte("alice")) {
		t.Fatal("bundle leaks the identity name in plaintext")
	}

	freshStore, freshTrust := newRecoveryEnv(t)
	got, err := recovery.Import(freshStore, freshTrust, fileBytes, []byte("bundle-password"), []byte("identity-password"), alice.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got.Trusted != 2 || got.Revoked != 1 {
		t.Fatalf("import summary = %+v, want 2 trusted, 1 revoked", got)
	}
	if _, err := freshStore.LoadPrivate(alice.Fingerprint, []byte("identity-password")); err != nil {
		t.Fatalf("restored private key does not unlock: %v", err)
	}
	if trusted, err := freshTrust.IsTrusted(alice.Fingerprint); err != nil || !trusted {
		t.Fatal("alice not trusted after import")
	}
	if trusted, err := freshTrust.IsTrusted(bob.Fingerprint); err != nil || trusted {
		t.Fatal("bob trusted after import, want revoked")
	}
}

func mustLoadPriv(t *testing.T, store *identity.Store, id *identity.Identity) *identity.PrivateIdentity {
	t.Helper()
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("identity-password"))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
