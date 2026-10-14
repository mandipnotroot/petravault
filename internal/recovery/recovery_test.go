// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package recovery_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"petravault/internal/identity"
	"petravault/internal/recovery"
	"petravault/internal/verify"
)

func newRecoveryEnv(t *testing.T) (*identity.Store, *identity.TrustStore, string) {
	t.Helper()
	root := t.TempDir()
	store := identity.NewStore(filepath.Join(root, "identities"))
	trust := identity.NewTrustStore(filepath.Join(root, "trust"))
	heads := filepath.Join(root, "heads")
	return store, trust, heads
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

func writeLiveHeads(t *testing.T, headsDir, repo, source, snapshot string) {
	t.Helper()
	if err := os.MkdirAll(headsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := verify.UpdateHead(filepath.Join(headsDir, repo+".json"), source, snapshot, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryExportImportRoundTrip(t *testing.T) {
	store, trust, heads := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	bob := mustRecoveryIdentity(t, store, trust, "bob")
	bobEnv, err := identity.SignRevocation(mustLoadPriv(t, store, alice), bob.Fingerprint, "left", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AddRevocation(bob.Fingerprint, bobEnv); err != nil {
		t.Fatal(err)
	}
	writeLiveHeads(t, heads, "repo-1", "laptop", "b3:"+strings.Repeat("ab", 32))

	fileBytes, summary, err := recovery.Export(store, trust, heads, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Trusted != 2 || summary.Revoked != 1 || summary.Heads != 1 {
		t.Fatalf("summary = %+v, want 2 trusted, 1 revoked, 1 heads", summary)
	}
	if bytes.Contains(fileBytes, []byte("alice")) {
		t.Fatal("bundle leaks the identity name in plaintext")
	}

	freshStore, freshTrust, freshHeads := newRecoveryEnv(t)
	got, err := recovery.Import(freshStore, freshTrust, freshHeads, fileBytes, []byte("bundle-password"), []byte("identity-password"), alice.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got.Trusted != 2 || got.Revoked != 1 || got.Heads != 1 {
		t.Fatalf("import summary = %+v, want 1 of each", got)
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
	statuses, _, err := recovery.Status(freshHeads, fileBytes, []byte("bundle-password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].State != "current" {
		t.Fatalf("statuses = %+v, want one current", statuses)
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

func TestRecoveryImportRejectsWrongPasswords(t *testing.T) {
	store, trust, heads := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	fileBytes, _, err := recovery.Export(store, trust, heads, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	freshStore, freshTrust, freshHeads := newRecoveryEnv(t)
	if _, err := recovery.Import(freshStore, freshTrust, freshHeads, fileBytes, []byte("wrong-password"), []byte("identity-password"), alice.Fingerprint); err == nil {
		t.Fatal("import opened the bundle with the wrong password")
	}
	if _, err := recovery.Import(freshStore, freshTrust, freshHeads, fileBytes, []byte("bundle-password"), []byte("wrong-password"), alice.Fingerprint); err == nil {
		t.Fatal("import verified the private key with the wrong password")
	}
}

func TestRecoveryImportRejectsTampering(t *testing.T) {
	store, trust, heads := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	fileBytes, _, err := recovery.Export(store, trust, heads, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(fileBytes)
	tampered[len(tampered)-1] ^= 0x01
	freshStore, freshTrust, freshHeads := newRecoveryEnv(t)
	if _, err := recovery.Import(freshStore, freshTrust, freshHeads, tampered, []byte("bundle-password"), []byte("identity-password"), alice.Fingerprint); err == nil {
		t.Fatal("import accepted a tampered bundle")
	}
}

func TestRecoveryStatusDetectsStaleness(t *testing.T) {
	store, trust, heads := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	writeLiveHeads(t, heads, "repo-1", "laptop", "b3:"+strings.Repeat("ab", 32))
	fileBytes, _, err := recovery.Export(store, trust, heads, alice.Fingerprint, []byte("bundle-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveHeads(t, heads, "repo-1", "laptop", "b3:"+strings.Repeat("cd", 32))
	statuses, _, err := recovery.Status(heads, fileBytes, []byte("bundle-password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].State != "diverged" {
		t.Fatalf("statuses = %+v, want one diverged", statuses)
	}
}

func TestRecoveryExportRejectsEmptyPassword(t *testing.T) {
	store, trust, heads := newRecoveryEnv(t)
	alice := mustRecoveryIdentity(t, store, trust, "alice")
	if _, _, err := recovery.Export(store, trust, heads, alice.Fingerprint, nil, nil); err == nil {
		t.Fatal("export sealed the bundle with an empty password")
	}
}
