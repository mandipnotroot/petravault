// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

func isIntegrity(err error) bool {
	return errors.Is(err, pverrors.ErrIntegrity)
}

func mustGenerate(t *testing.T) crypto.SecretKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	ad := crypto.AssociatedData("repo-id", "chunk", "b3:abc")
	for _, plaintext := range [][]byte{
		[]byte("backup chunk bytes"),
		{},
		bytes.Repeat([]byte("x"), 1<<20),
	} {
		sealed, err := key.Seal(plaintext, ad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := key.Open(sealed, ad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip of %d bytes mismatched", len(plaintext))
		}
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	ad := crypto.AssociatedData("repo-id", "chunk", "b3:abc")
	first, err := key.Seal([]byte("same"), ad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := key.Seal([]byte("same"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals are identical, want a fresh random nonce per object")
	}
	for _, sealed := range [][]byte{first, second} {
		if _, err := key.Open(sealed, ad); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	ad := crypto.AssociatedData("repo-id", "snapshot", "b3:snap")
	sealed, err := key.Seal([]byte("manifest bytes"), ad)
	if err != nil {
		t.Fatal(err)
	}

	tampered := func(i int) []byte {
		out := bytes.Clone(sealed)
		out[i] ^= 0x01
		return out
	}
	for _, tt := range []struct {
		name   string
		sealed []byte
	}{
		{name: "nonce", sealed: tampered(0)},
		{name: "ciphertext", sealed: tampered(crypto.NonceLength)},
		{name: "tag", sealed: tampered(len(sealed) - 1)},
		{name: "truncated", sealed: sealed[:len(sealed)-1]},
		{name: "empty", sealed: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := key.Open(tt.sealed, ad)
			if err == nil {
				t.Fatal("Open accepted tampered blob, want authentication failure")
			}
			if !strings.Contains(err.Error(), "authentication failed") {
				t.Fatalf("err = %v, want authentication failure", err)
			}
			if len(got) != 0 {
				t.Fatal("Open returned plaintext on failure, want none")
			}
		})
	}
}

func TestOpenRejectsWrongKeyAndAD(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	other := mustGenerate(t)
	ad := crypto.AssociatedData("repo-id", "chunk", "b3:abc")
	sealed, err := key.Seal([]byte("chunk bytes"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed, ad); err == nil {
		t.Fatal("Open with the wrong key succeeded, want failure")
	}
	if _, err := key.Open(sealed, crypto.AssociatedData("other-repo", "chunk", "b3:abc")); err == nil {
		t.Fatal("Open with a different repository succeeded, want failure")
	}
	if _, err := key.Open(sealed, crypto.AssociatedData("repo-id", "chunk", "b3:other")); err == nil {
		t.Fatal("Open with a different chunk ID succeeded, want failure")
	}
}

func TestAuthFailureMapsToIntegrity(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	_, err := key.Open([]byte("too short"), crypto.AssociatedData("r", "chunk", "c"))
	if err == nil {
		t.Fatal("Open accepted garbage, want failure")
	}
	if !isIntegrity(err) {
		t.Fatalf("err = %v, want integrity failure (exit 4)", err)
	}
	if got := pverrors.ExitCode(err); got != pverrors.ExitIntegrity {
		t.Fatalf("ExitCode = %d, want %d", got, pverrors.ExitIntegrity)
	}
}

func TestAssociatedDataBindsFields(t *testing.T) {
	t.Parallel()

	base := crypto.AssociatedData("repo", "chunk", "id")
	for _, other := range [][]byte{
		crypto.AssociatedData("other", "chunk", "id"),
		crypto.AssociatedData("repo", "snapshot", "id"),
		crypto.AssociatedData("repo", "chunk", "other"),
		crypto.AssociatedData("repo", "chunk", ""),
	} {
		if bytes.Equal(base, other) {
			t.Fatal("AssociatedData ignores a bound field, want domain separation")
		}
	}
	// Length-prefixing keeps ("ab","c") distinct from ("a","bc").
	if bytes.Equal(
		crypto.AssociatedData("ab", "c", "x"),
		crypto.AssociatedData("a", "bc", "x"),
	) {
		t.Fatal("AssociatedData encoding is ambiguous across field boundaries")
	}
	if !bytes.Equal(base, crypto.AssociatedData("repo", "chunk", "id")) {
		t.Fatal("AssociatedData is not deterministic")
	}
}

func TestSecretKeyRedacted(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	if got := fmt.Sprint(key); got != "[redacted]" {
		t.Fatalf("String = %q, want redaction", got)
	}
	if got := fmt.Sprintf("%#v", key); got != "[redacted]" {
		t.Fatalf("GoString = %q, want redaction", got)
	}
	if got := key.LogValue(); got.String() != "[redacted]" {
		t.Fatalf("LogValue = %q, want redaction", got.String())
	}
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("using key", slog.Any("key", key))
	if strings.Contains(buf.String(), "b:") || len(buf.String()) > 100 {
		t.Fatalf("log line leaks key material: %q", buf.String())
	}
}

func TestSecretKeyZeroAndEqual(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t)
	other := mustGenerate(t)
	clone := key
	if !key.Equal(clone) {
		t.Fatal("key does not equal its copy")
	}
	if key.Equal(other) {
		t.Fatal("two random keys compare equal")
	}
	key.Zero()
	var zero crypto.SecretKey
	if !key.Equal(zero) {
		t.Fatal("zeroed key is not all zeros")
	}
}

func TestNewKeyFromBytesRejectsBadLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := crypto.NewKeyFromBytes(make([]byte, n)); err == nil {
			t.Fatalf("NewKeyFromBytes accepted %d bytes, want rejection", n)
		}
	}
}

func TestGenerateKeyUnique(t *testing.T) {
	t.Parallel()

	first := mustGenerate(t)
	second := mustGenerate(t)
	if first.Equal(second) {
		t.Fatal("two generated keys compare equal")
	}
}
