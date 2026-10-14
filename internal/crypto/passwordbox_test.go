// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"petravault/internal/crypto"
)

// Serial tests: Lock and Unlock each pay the full OWASP Argon2id cost, so
// they run one at a time to bound peak memory.

func TestLockUnlockRoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	secret := []byte("identity private key bytes")

	locked, err := crypto.Lock(password, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(locked, secret) {
		t.Fatal("envelope contains the plaintext secret")
	}
	if bytes.Contains(locked, password) {
		t.Fatal("envelope contains the password")
	}
	opened, err := crypto.Unlock(password, locked)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatal("Unlock did not return the locked secret")
	}
}

func TestUnlockWrongPasswordFails(t *testing.T) {
	locked, err := crypto.Lock([]byte("right password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := crypto.Unlock([]byte("wrong password"), locked)
	if err == nil {
		t.Fatal("Unlock accepted the wrong password, want failure")
	}
	if len(opened) != 0 {
		t.Fatal("Unlock returned plaintext on failure, want none")
	}
}

func TestUnlockTamperedEnvelopeFails(t *testing.T) {
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := flipSealedChar(t, locked)
	opened, err := crypto.Unlock([]byte("password"), tampered)
	if err == nil {
		t.Fatal("Unlock accepted a tampered envelope, want failure")
	}
	if len(opened) != 0 {
		t.Fatal("Unlock returned plaintext on failure, want none")
	}
}

// flipSealedChar flips one base64 character inside the sealed blob without
// breaking the JSON framing, so the tamper reaches AEAD verification.
func flipSealedChar(t *testing.T, locked []byte) []byte {
	t.Helper()
	const marker = `"sealed":"`
	i := bytes.Index(locked, []byte(marker))
	if i < 0 {
		t.Fatal("envelope has no sealed field")
	}
	j := i + len(marker)
	if j >= len(locked) {
		t.Fatal("sealed field is empty")
	}
	out := bytes.Clone(locked)
	if out[j] == 'A' {
		out[j] = 'B'
	} else {
		out[j] = 'A'
	}
	return out
}

func TestUnlockRejectsUnknownFields(t *testing.T) {
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(locked, []byte(`"version":2`), []byte(`"version":2,"extra":true`), 1)
	if _, err := crypto.Unlock([]byte("password"), withExtra); err == nil {
		t.Fatal("Unlock accepted an unknown envelope field, want rejection")
	}
}

func TestUnlockRejectsBadEnvelope(t *testing.T) {
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		locked []byte
	}{
		{name: "garbage", locked: []byte("not json")},
		{name: "trailing data", locked: append(bytes.Clone(locked), []byte(" {}")...)},
		{name: "wrong version", locked: bytes.Replace(locked, []byte(`"version":2`), []byte(`"version":99`), 1)},
		{name: "empty", locked: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := crypto.Unlock([]byte("password"), tt.locked); err == nil {
				t.Fatalf("Unlock accepted %s, want rejection", tt.name)
			}
		})
	}
}

func TestLockRejectsEmptyPassword(t *testing.T) {
	if _, err := crypto.Lock(nil, []byte("secret")); err == nil {
		t.Fatal("Lock accepted an empty password, want rejection")
	}
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Unlock(nil, locked); err == nil {
		t.Fatal("Unlock accepted an empty password, want rejection")
	}
}

func TestLockEnvelopeCarriesParams(t *testing.T) {
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"version":`, `"memory_kib":`, `"salt":`, `"sealed":`} {
		if !strings.Contains(string(locked), field) {
			t.Fatalf("envelope misses %s", field)
		}
	}
}

func TestUnlockTamperedParamsFailClosed(t *testing.T) {
	locked, err := crypto.Lock([]byte("password"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// The envelope must name version 2.
	if !bytes.Contains(locked, []byte(`"version":2`)) {
		t.Fatal("envelope does not name version 2")
	}
	// Weakening the Argon2id parameters keeps the JSON valid, so the
	// tamper reaches authentication: it must fail closed as an
	// integrity failure, never open under the substituted parameters.
	weakened := bytes.Replace(locked, []byte(`"threads":4`), []byte(`"threads":5`), 1)
	if bytes.Equal(weakened, locked) {
		t.Fatal("envelope has no threads field to weaken")
	}
	opened, err := crypto.Unlock([]byte("password"), weakened)
	if err == nil {
		t.Fatal("Unlock opened an envelope with substituted parameters, want failure")
	}
	if len(opened) != 0 {
		t.Fatal("Unlock returned plaintext on failure, want none")
	}
	if !isIntegrity(err) {
		t.Fatalf("substituted-parameter error = %v, want an integrity failure", err)
	}
	// The salt is bound the same way.
	salted := flipFieldChar(t, locked, `"salt":"`)
	if _, err := crypto.Unlock([]byte("password"), salted); err == nil {
		t.Fatal("Unlock opened an envelope with a substituted salt, want failure")
	}
}

// TestUnlockV1EnvelopeStillOpens pins backward compatibility: envelopes
// sealed under the legacy static context open, while the same tampering
// applied to them fails closed.
func TestUnlockV1EnvelopeStillOpens(t *testing.T) {
	password := []byte("password")
	secret := []byte("legacy secret")
	salt := bytes.Repeat([]byte{0x5a}, crypto.SaltLength)
	kek, err := crypto.DeriveKEK(password, salt, crypto.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	defer kek.Zero()
	sealed, err := kek.Seal(secret, []byte(crypto.ContextKeystore))
	if err != nil {
		t.Fatal(err)
	}
	locked := []byte(fmt.Sprintf(
		`{"version":1,"time":%d,"memory_kib":%d,"threads":%d,"salt":"%s","sealed":"%s"}`,
		3, 65536, 4,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(sealed)))
	opened, err := crypto.Unlock(password, locked)
	if err != nil {
		t.Fatalf("Unlock rejected a legacy version 1 envelope: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatal("Unlock did not return the legacy secret")
	}
	// A version byte flipped from 1 to 2 must not open: the blob was
	// sealed under the version 1 associated data.
	downgraded := bytes.Replace(locked, []byte(`"version":1`), []byte(`"version":2`), 1)
	if _, err := crypto.Unlock(password, downgraded); err == nil {
		t.Fatal("Unlock opened a version-flipped envelope, want failure")
	}
}

// flipFieldChar flips one base64 character inside the named envelope field,
// keeping the JSON framing valid.
func flipFieldChar(t *testing.T, locked []byte, marker string) []byte {
	t.Helper()
	i := bytes.Index(locked, []byte(marker))
	if i < 0 {
		t.Fatalf("envelope has no %s field", marker)
	}
	j := i + len(marker)
	if j >= len(locked) {
		t.Fatalf("envelope field %s is empty", marker)
	}
	out := bytes.Clone(locked)
	if out[j] == 'A' {
		out[j] = 'B'
	} else {
		out[j] = 'A'
	}
	return out
}
