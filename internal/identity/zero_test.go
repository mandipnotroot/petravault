// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Zero is best effort by nature (garbage-collected copies may survive), so
// this pins the observable contract: nil-safe, idempotent, public identity
// intact, signing key struct cleared, KEM key detached.

func TestPrivateIdentityZero(t *testing.T) {
	t.Parallel()

	store := NewStore(filepath.Join(t.TempDir(), "identities"))
	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	id, err := store.Create("alice", []byte("test-password"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	if priv.signPriv == nil {
		t.Fatal("loaded identity has no signing key")
	}
	before := *priv.signPriv
	priv.Zero()
	if reflect.DeepEqual(before, *priv.signPriv) {
		t.Fatal("Zero left the signing key struct unchanged")
	}
	if priv.KEMPrivate() != nil {
		t.Fatal("Zero left the KEM private key attached")
	}
	if !priv.Fingerprint().Equal(id.Fingerprint) {
		t.Fatal("Zero disturbed the public fingerprint")
	}
	priv.Zero()
	var nilPriv *PrivateIdentity
	nilPriv.Zero()
}
