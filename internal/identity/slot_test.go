// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	"petravault/internal/identity"

	pverrors "petravault/internal/errors"
)

func newSlotStores(t *testing.T) (*identity.Store, *identity.Store) {
	t.Helper()
	return identity.NewStore(filepath.Join(t.TempDir(), "a")),
		identity.NewStore(filepath.Join(t.TempDir(), "b"))
}

func mustSlotIdentity(t *testing.T, store *identity.Store, name, password string) (*identity.PrivateIdentity, *identity.Identity) {
	t.Helper()
	id, err := store.Create(name, []byte(password), testTime)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := store.LoadPrivate(id.Fingerprint, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return priv, id
}

func trustedLookup(t *testing.T, ids ...*identity.Identity) func(string) ([]byte, error) {
	t.Helper()
	m := make(map[string][]byte, len(ids))
	for _, id := range ids {
		m[id.Fingerprint.String()] = id.SignPublic
	}
	return func(granter string) ([]byte, error) {
		pub, ok := m[granter]
		if !ok {
			return nil, errors.Join(pverrors.ErrUntrustedSigner, errors.New("unknown granter"))
		}
		return pub, nil
	}
}

func TestSlotSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	aliceStore, bobStore := newSlotStores(t)
	alicePriv, _ := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")

	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(alicePriv, "repo-1", bobID, master)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := bobStore.LoadPrivate(bobID.Fingerprint, []byte("pw-bob"))
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := aliceStore.LoadPublic(alicePriv.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.OpenSlotTrusted(env, "repo-1", bobID.Fingerprint, bobPriv.KEMPrivate(), trustedLookup(t, alicePub))
	if err != nil {
		t.Fatal(err)
	}
	if !master.Equal(got) {
		t.Fatal("opened master does not match")
	}
}

func TestSlotSelfGrant(t *testing.T) {
	t.Parallel()

	store, _ := newSlotStores(t)
	priv, id := mustSlotIdentity(t, store, "alice", "password")
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(priv, "repo-1", id, master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.OpenSlotTrusted(env, "repo-1", id.Fingerprint, priv.KEMPrivate(), trustedLookup(t, id))
	if err != nil {
		t.Fatal(err)
	}
	if !master.Equal(got) {
		t.Fatal("self-grant did not round-trip")
	}
}

func TestSlotOpenRejectsUntrustedGranter(t *testing.T) {
	t.Parallel()

	malloryStore, bobStore := newSlotStores(t)
	malloryPriv, _ := mustSlotIdentity(t, malloryStore, "mallory", "pw-mallory")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")

	// Mallory seals her own master key for Bob. Bob trusts only Alice, so
	// the grant must be rejected even though the signature is valid.
	malloryMaster, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(malloryPriv, "repo-1", bobID, malloryMaster)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := bobStore.LoadPrivate(bobID.Fingerprint, []byte("pw-bob"))
	if err != nil {
		t.Fatal(err)
	}
	aliceStore, _ := newSlotStores(t)
	_, aliceID := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	if _, err := identity.OpenSlotTrusted(env, "repo-1", bobID.Fingerprint, bobPriv.KEMPrivate(), trustedLookup(t, aliceID)); err == nil {
		t.Fatal("OpenSlotTrusted accepted a slot from an untrusted granter")
	} else if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("err = %v, want untrusted signer", err)
	}
}

func TestSlotOpenRejectsWrongRepoAndMember(t *testing.T) {
	t.Parallel()

	aliceStore, bobStore := newSlotStores(t)
	alicePriv, _ := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(alicePriv, "repo-1", bobID, master)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := bobStore.LoadPrivate(bobID.Fingerprint, []byte("pw-bob"))
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := aliceStore.LoadPublic(alicePriv.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	lookup := trustedLookup(t, alicePub)
	if _, err := identity.OpenSlotTrusted(env, "repo-2", bobID.Fingerprint, bobPriv.KEMPrivate(), lookup); err == nil {
		t.Fatal("OpenSlotTrusted accepted a replay into another repository")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("repo-mismatch err = %v, want integrity failure", err)
	}
	otherStore := identity.NewStore(filepath.Join(t.TempDir(), "carol"))
	_, carolID := mustSlotIdentity(t, otherStore, "carol", "pw-carol")
	carolPriv, err := otherStore.LoadPrivate(carolID.Fingerprint, []byte("pw-carol"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.OpenSlotTrusted(env, "repo-1", carolID.Fingerprint, carolPriv.KEMPrivate(), lookup); err == nil {
		t.Fatal("OpenSlotTrusted accepted a slot for another member")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("member-mismatch err = %v, want integrity failure", err)
	}
}

func TestSlotRejectsTamperedEnvelope(t *testing.T) {
	t.Parallel()

	aliceStore, bobStore := newSlotStores(t)
	alicePriv, _ := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := identity.SealSlot(alicePriv, "repo-1", bobID, master)
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := bobStore.LoadPrivate(bobID.Fingerprint, []byte("pw-bob"))
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := aliceStore.LoadPublic(alicePriv.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	lookup := trustedLookup(t, alicePub)
	tampered := bytes.Clone(env)
	tampered[len(tampered)-10] ^= 0x01
	if _, err := identity.OpenSlotTrusted(tampered, "repo-1", bobID.Fingerprint, bobPriv.KEMPrivate(), lookup); err == nil {
		t.Fatal("OpenSlotTrusted accepted a tampered envelope")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("tampered err = %v, want integrity failure", err)
	}
}

func TestSlotRejectsWrongContextSignature(t *testing.T) {
	t.Parallel()

	aliceStore, bobStore := newSlotStores(t)
	alicePriv, _ := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Sign an otherwise valid slot payload under the manifest context: it
	// must never verify as a slot grant (DESIGN.md §4.3).
	sealed, err := crypto.SealMaster(master, bobID.KEMPublic, "repo-1", bobID.Fingerprint.String())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"version": 1, "repository_id": "repo-1",
		"member": bobID.Fingerprint.String(), "granter": alicePriv.Fingerprint().String(),
		"kem": crypto.KEMID, "kdf": crypto.SlotKDFID, "aead": crypto.SlotAEADID,
		"sealed": base64.StdEncoding.EncodeToString(sealed),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := alicePriv.Sign(crypto.ContextManifest, payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]string{
		"payload":   base64.StdEncoding.EncodeToString(payload),
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := aliceStore.LoadPublic(alicePriv.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifySlot(env, alicePub.SignPublic); err == nil {
		t.Fatal("VerifySlot accepted a manifest-context signature")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("context err = %v, want integrity failure", err)
	}
}

func TestSlotKeyRoundTrip(t *testing.T) {
	t.Parallel()

	store, _ := newSlotStores(t)
	_, id := mustSlotIdentity(t, store, "alice", "password")
	key := identity.SlotKey(id.Fingerprint)
	if key != "keys/"+id.Fingerprint.String()+".slot" {
		t.Fatalf("SlotKey = %q", key)
	}
	got, err := identity.ParseSlotKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(id.Fingerprint) {
		t.Fatal("slot key did not round-trip")
	}
	for _, bad := range []string{"", "keys/", "keys/short.slot", "packs/abc", "keys/" + id.Fingerprint.String()} {
		if _, err := identity.ParseSlotKey(bad); err == nil {
			t.Fatalf("ParseSlotKey(%q) accepted, want error", bad)
		}
	}
}

func TestSlotSealRejectsBadInput(t *testing.T) {
	t.Parallel()

	aliceStore, bobStore := newSlotStores(t)
	alicePriv, _ := mustSlotIdentity(t, aliceStore, "alice", "pw-alice")
	_, bobID := mustSlotIdentity(t, bobStore, "bob", "pw-bob")
	master, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.SealSlot(nil, "repo-1", bobID, master); err == nil {
		t.Fatal("SealSlot accepted a nil granter")
	}
	if _, err := identity.SealSlot(alicePriv, "repo-1", nil, master); err == nil {
		t.Fatal("SealSlot accepted a nil member")
	}
	if _, err := identity.SealSlot(alicePriv, "", bobID, master); err == nil {
		t.Fatal("SealSlot accepted an empty repository id")
	}
}
