// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"bytes"
	"crypto/hpke"
	"crypto/mldsa"
	"errors"
	"strings"
	"testing"
	"time"

	"petravault/internal/crypto"
	"petravault/internal/identity"

	pverrors "petravault/internal/errors"
)

func testTime() time.Time {
	return time.Date(2026, time.October, 13, 10, 0, 0, 0, time.UTC)
}

func testKeys(t *testing.T) (signPub, kemPub []byte) {
	t.Helper()
	signPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	kemPriv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return signPriv.PublicKey().Bytes(), kemPriv.PublicKey().Bytes()
}

func TestFingerprintDeterministic(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	first, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("same keys produced different fingerprints")
	}
}

func TestFingerprintSensitiveToKeys(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	base, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	otherSign, _ := testKeys(t)
	other, err := identity.ComputeFingerprint(otherSign, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	if base.Equal(other) {
		t.Fatal("different signing keys produced the same fingerprint")
	}
	_, otherKem := testKeys(t)
	other, err = identity.ComputeFingerprint(signPub, otherKem)
	if err != nil {
		t.Fatal(err)
	}
	if base.Equal(other) {
		t.Fatal("different KEM keys produced the same fingerprint")
	}
}

func TestFingerprintRejectsBadLengths(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	if _, err := identity.ComputeFingerprint(signPub[:len(signPub)-1], kemPub); err == nil {
		t.Fatal("ComputeFingerprint accepted a short signing key")
	}
	if _, err := identity.ComputeFingerprint(signPub, kemPub[:len(kemPub)-1]); err == nil {
		t.Fatal("ComputeFingerprint accepted a short KEM key")
	}
}

func TestFingerprintStringRoundTrip(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	plain := fp.String()
	if len(plain) != 52 {
		t.Fatalf("String length = %d, want 52", len(plain))
	}
	for _, form := range []string{
		plain,
		strings.ToUpper(plain),
		fp.Grouped(),
		strings.ToUpper(fp.Grouped()),
		"b3:" + plain,
		"b3:" + fp.Grouped(),
		"  " + fp.Grouped() + "  ",
	} {
		got, err := identity.ParseFingerprint(form)
		if err != nil {
			t.Fatalf("ParseFingerprint(%q) failed: %v", form, err)
		}
		if !got.Equal(fp) {
			t.Fatalf("ParseFingerprint(%q) mismatch", form)
		}
	}
}

func TestFingerprintGroupedFormat(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	grouped := fp.Grouped()
	if strings.Count(grouped, "-") != 12 {
		t.Fatalf("Grouped = %q, want 12 dashes", grouped)
	}
	if strings.ReplaceAll(grouped, "-", "") != fp.String() {
		t.Fatalf("Grouped strips to %q, want %q", strings.ReplaceAll(grouped, "-", ""), fp.String())
	}
}

func TestParseFingerprintRejectsAbbreviated(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	for _, short := range []string{"", "abcd", fp.String()[:16], fp.String()[:51]} {
		if _, err := identity.ParseFingerprint(short); err == nil {
			t.Fatalf("ParseFingerprint(%q) accepted an abbreviated value", short)
		}
	}
}

func TestParseFingerprintHexForm(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	raw := fp
	hexForm := "b3:" + strings.ToLower(hexOf(t, raw[:]))
	got, err := identity.ParseFingerprint(hexForm)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(fp) {
		t.Fatal("hex form did not round-trip")
	}
}

func hexOf(t *testing.T, b []byte) string {
	t.Helper()
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("revocation payload bytes")
	sig, err := identity.Sign(priv, crypto.ContextRevocation, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != identity.SignSignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), identity.SignSignatureSize)
	}
	if err := identity.Verify(priv.PublicKey().Bytes(), crypto.ContextRevocation, msg, sig); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestVerifyRejectsWrongContext(t *testing.T) {
	t.Parallel()

	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("manifest bytes")
	sig, err := identity.Sign(priv, crypto.ContextManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(priv.PublicKey().Bytes(), crypto.ContextRevocation, msg, sig); err == nil {
		t.Fatal("Verify accepted a signature under the wrong context")
	} else if !isIntegrity(err) {
		t.Fatalf("wrong-context error = %v, want integrity failure", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload")
	sig, err := identity.Sign(priv, crypto.ContextManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0x01
	if err := identity.Verify(priv.PublicKey().Bytes(), crypto.ContextManifest, msg, sig); err == nil {
		t.Fatal("Verify accepted a tampered signature")
	} else if !isIntegrity(err) {
		t.Fatalf("tampered error = %v, want integrity failure", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	t.Parallel()

	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	other, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := identity.Sign(priv, crypto.ContextManifest, []byte("msg"))
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(other.PublicKey().Bytes(), crypto.ContextManifest, []byte("msg"), sig); err == nil {
		t.Fatal("Verify accepted a signature under the wrong key")
	}
}

func TestMarshalParsePublicRoundTrip(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	id := &identity.Identity{
		Fingerprint: fp,
		Name:        "alice",
		CreatedAt:   testTime(),
		SignPublic:  signPub,
		KEMPublic:   kemPub,
	}
	data, err := identity.MarshalPublic(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, signPub) {
		t.Fatal("public file contains raw key bytes outside base64")
	}
	got, err := identity.ParsePublic(data)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Fingerprint.Equal(fp) || got.Name != "alice" || !got.CreatedAt.Equal(id.CreatedAt.UTC()) {
		t.Fatal("parsed identity does not match")
	}
	if !bytes.Equal(got.SignPublic, signPub) || !bytes.Equal(got.KEMPublic, kemPub) {
		t.Fatal("parsed keys do not match")
	}
}

func TestParsePublicRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	data, err := identity.MarshalPublic(&identity.Identity{
		Fingerprint: fp,
		Name:        "alice",
		CreatedAt:   testTime(),
		SignPublic:  signPub,
		KEMPublic:   kemPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1)
	if _, err := identity.ParsePublic(withExtra); err == nil {
		t.Fatal("ParsePublic accepted an unknown field")
	}
}

func TestParsePublicRejectsFingerprintMismatch(t *testing.T) {
	t.Parallel()

	signPub, kemPub := testKeys(t)
	fp, err := identity.ComputeFingerprint(signPub, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	otherSign, _ := testKeys(t)
	otherFP, err := identity.ComputeFingerprint(otherSign, kemPub)
	if err != nil {
		t.Fatal(err)
	}
	data, err := identity.MarshalPublic(&identity.Identity{
		Fingerprint: otherFP,
		Name:        "mallory",
		CreatedAt:   testTime(),
		SignPublic:  signPub,
		KEMPublic:   kemPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = fp
	if _, err := identity.ParsePublic(data); err == nil {
		t.Fatal("ParsePublic accepted a fingerprint mismatch")
	} else if !isIntegrity(err) {
		t.Fatalf("mismatch error = %v, want integrity failure", err)
	}
}

func isIntegrity(err error) bool {
	return errors.Is(err, pverrors.ErrIntegrity)
}
