// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"petravault/internal/identity"
)

func newTestStore(t *testing.T) (*identity.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identities")
	return identity.NewStore(dir), dir
}

func TestKeystoreCreateRoundTrip(t *testing.T) {
	store, _ := newTestStore(t)
	password := []byte("correct horse battery staple")
	id, err := store.Create("alice", password, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "alice" {
		t.Fatalf("name = %q, want alice", id.Name)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, password)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Fingerprint().Equal(id.Fingerprint) {
		t.Fatal("private fingerprint mismatch")
	}
	msg := []byte("hello")
	sig, err := priv.Sign("petravault manifest v1", msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(id.SignPublic, "petravault manifest v1", msg, sig); err != nil {
		t.Fatalf("verify after load failed: %v", err)
	}
}

func TestKeystoreWrongPasswordFails(t *testing.T) {
	store, _ := newTestStore(t)
	id, err := store.Create("alice", []byte("right password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPrivate(id.Fingerprint, []byte("wrong password")); err == nil {
		t.Fatal("LoadPrivate accepted the wrong password")
	}
}

func TestKeystoreSealedHidesSecrets(t *testing.T) {
	store, dir := newTestStore(t)
	password := []byte("s3cret-password")
	id, err := store.Create("alice", password, testTime)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, id.Fingerprint.String(), "private.sealed"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, password) {
		t.Fatal("sealed file contains the password")
	}
}

func TestKeystorePrivateFilePermissions(t *testing.T) {
	store, dir := newTestStore(t)
	password := []byte("password")
	id, err := store.Create("alice", password, testTime)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, id.Fingerprint.String(), "private.sealed"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private file permissions %v too open", fi.Mode().Perm())
	}
}

func TestKeystorePrivatePermissionsRefused(t *testing.T) {
	store, dir := newTestStore(t)
	password := []byte("password")
	id, err := store.Create("alice", password, testTime)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id.Fingerprint.String(), "private.sealed")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadPrivate(id.Fingerprint, password); err == nil {
		t.Fatal("LoadPrivate accepted a group-readable private file")
	}
	if os.Getuid() == 0 {
		t.Log("running as root; chmod refusal still enforced by the check above")
	}
}

func TestKeystoreListAndFind(t *testing.T) {
	store, _ := newTestStore(t)
	alice, err := store.Create("alice", []byte("pw-alice"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Create("bob", []byte("pw-bob"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("list = %d identities, want 2", len(listed))
	}
	for _, e := range listed {
		if !e.Owned {
			t.Fatal("created identity is not marked owned")
		}
	}
	found, err := store.Find("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !found.Fingerprint.Equal(alice.Fingerprint) {
		t.Fatal("Find by name mismatch")
	}
	found, err = store.Find(bob.Fingerprint.String())
	if err != nil {
		t.Fatal(err)
	}
	if !found.Fingerprint.Equal(bob.Fingerprint) {
		t.Fatal("Find by fingerprint mismatch")
	}
	found, err = store.Find(bob.Fingerprint.Grouped())
	if err != nil {
		t.Fatal(err)
	}
	if !found.Fingerprint.Equal(bob.Fingerprint) {
		t.Fatal("Find by grouped fingerprint mismatch")
	}
	if _, err := store.Find("carol"); err == nil {
		t.Fatal("Find accepted an unknown name")
	}
}

func TestKeystoreExportImport(t *testing.T) {
	src, _ := newTestStore(t)
	id, err := src.Create("alice", []byte("password"), testTime)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := src.Export(id.Fingerprint, &buf); err != nil {
		t.Fatal(err)
	}
	dst, _ := newTestStore(t)
	imported, err := dst.Import(bytes.Clone(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !imported.Fingerprint.Equal(id.Fingerprint) {
		t.Fatal("imported fingerprint mismatch")
	}
	listed, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Owned {
		t.Fatal("imported identity should be public-only")
	}
}

func TestKeystoreCreateRejectsBadName(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Create("", []byte("password"), testTime); err == nil {
		t.Fatal("Create accepted an empty name")
	}
}

func TestKeystoreCreateRejectsEmptyPassword(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Create("alice", nil, testTime); err == nil {
		t.Fatal("Create accepted an empty password")
	}
}
