// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"testing"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

func mustKEMKey(t *testing.T) (hpke.PrivateKey, []byte) {
	t.Helper()
	priv, err := crypto.SlotKEM().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.PublicKey().Bytes()
}

func TestSlotSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	priv, pub := mustKEMKey(t)
	sealed, err := crypto.SealMaster(master, pub, "repo-1", "member-fp")
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 {
		t.Fatal("SealMaster returned no bytes")
	}
	got, err := crypto.OpenMaster(sealed, priv, "repo-1", "member-fp")
	if err != nil {
		t.Fatal(err)
	}
	if !master.Equal(got) {
		t.Fatal("opened master does not match")
	}
}

func TestSlotSealUsesFreshEncapsulation(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	_, pub := mustKEMKey(t)
	first, err := crypto.SealMaster(master, pub, "repo-1", "member")
	if err != nil {
		t.Fatal(err)
	}
	second, err := crypto.SealMaster(master, pub, "repo-1", "member")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals are identical, want fresh HPKE encapsulation per slot")
	}
}

func TestSlotOpenRejectsWrongBinding(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	priv, pub := mustKEMKey(t)
	sealed, err := crypto.SealMaster(master, pub, "repo-1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		repo string
		mbr  string
	}{
		{name: "repo", repo: "repo-2", mbr: "alice"},
		{name: "member", repo: "repo-1", mbr: "bob"},
		{name: "both", repo: "repo-2", mbr: "bob"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := crypto.OpenMaster(sealed, priv, tt.repo, tt.mbr); err == nil {
				t.Fatal("OpenMaster accepted the wrong binding")
			} else if !errors.Is(err, pverrors.ErrIntegrity) {
				t.Fatalf("err = %v, want integrity failure", err)
			}
		})
	}
}

func TestSlotOpenRejectsWrongKeyAndTampering(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	priv, pub := mustKEMKey(t)
	sealed, err := crypto.SealMaster(master, pub, "repo-1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.SlotKEM().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.OpenMaster(sealed, other, "repo-1", "alice"); err == nil {
		t.Fatal("OpenMaster accepted the wrong private key")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("wrong-key err = %v, want integrity failure", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := crypto.OpenMaster(tampered, priv, "repo-1", "alice"); err == nil {
		t.Fatal("OpenMaster accepted tampered bytes")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("tampered err = %v, want integrity failure", err)
	}
	if _, err := crypto.OpenMaster(nil, priv, "repo-1", "alice"); err == nil {
		t.Fatal("OpenMaster accepted empty bytes")
	}
}

func TestSlotInfoBindsFields(t *testing.T) {
	t.Parallel()

	base := crypto.SlotInfo("repo", "alice")
	for _, other := range [][]byte{
		crypto.SlotInfo("other", "alice"),
		crypto.SlotInfo("repo", "bob"),
		crypto.SlotInfo("repo", ""),
	} {
		if bytes.Equal(base, other) {
			t.Fatal("SlotInfo ignores a bound field")
		}
	}
	if bytes.Equal(crypto.SlotInfo("ab", "c"), crypto.SlotInfo("a", "bc")) {
		t.Fatal("SlotInfo encoding is ambiguous across field boundaries")
	}
	if !bytes.Equal(base, crypto.SlotInfo("repo", "alice")) {
		t.Fatal("SlotInfo is not deterministic")
	}
}

func TestSlotSuiteIDsFrozen(t *testing.T) {
	t.Parallel()

	if crypto.KEMID != "mlkem768-x25519" {
		t.Fatalf("KEMID = %q, want mlkem768-x25519", crypto.KEMID)
	}
	if crypto.SlotKDFID != "hkdf-sha256" {
		t.Fatalf("SlotKDFID = %q", crypto.SlotKDFID)
	}
	if crypto.SlotAEADID != "chacha20poly1305" {
		t.Fatalf("SlotAEADID = %q", crypto.SlotAEADID)
	}
	if crypto.SlotInfoContext != "petravault key-slot v1" {
		t.Fatalf("SlotInfoContext = %q", crypto.SlotInfoContext)
	}
	// Numeric HPKE identifiers come from RFC 9180 (KDF/AEAD) and
	// draft-ietf-hpke-pq (X-Wing KEM). Pin them so an identifier change is a
	// detected migration, not silent breakage (DESIGN.md §4.2).
	if got := crypto.SlotKEM().ID(); got != 25722 {
		t.Fatalf("KEM ID = %d, want 25722 (X-Wing draft identifier)", got)
	}
	if got := crypto.SlotKDF().ID(); got != 1 {
		t.Fatalf("KDF ID = %d, want 1 (HKDF-SHA256)", got)
	}
	if got := crypto.SlotAEAD().ID(); got != 3 {
		t.Fatalf("AEAD ID = %d, want 3 (ChaCha20Poly1305)", got)
	}
}

func TestSlotWireSizesPinned(t *testing.T) {
	t.Parallel()

	priv, pub := mustKEMKey(t)
	if len(pub) != 1216 {
		t.Fatalf("KEM public length = %d, want 1216", len(pub))
	}
	raw, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("KEM private length = %d, want 32", len(raw))
	}
	master := mustGenerate(t)
	sealed, err := crypto.SealMaster(master, pub, "repo-1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// enc (1120) + 32-byte master + 16-byte tag.
	if len(sealed) != 1168 {
		t.Fatalf("sealed length = %d, want 1168", len(sealed))
	}
}

func TestSlotSealRejectsBadInput(t *testing.T) {
	t.Parallel()

	master := mustGenerate(t)
	_, pub := mustKEMKey(t)
	if _, err := crypto.SealMaster(master, pub, "", "alice"); err == nil {
		t.Fatal("SealMaster accepted an empty repository id")
	}
	if _, err := crypto.SealMaster(master, pub, "repo-1", ""); err == nil {
		t.Fatal("SealMaster accepted an empty member")
	}
	if _, err := crypto.SealMaster(master, []byte("short"), "repo-1", "alice"); err == nil {
		t.Fatal("SealMaster accepted a malformed recipient key")
	}
	if _, err := crypto.OpenMaster([]byte("x"), nil, "repo-1", "alice"); err == nil {
		t.Fatal("OpenMaster accepted a nil private key")
	}
}
