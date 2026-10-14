// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package crypto_test

import (
	"bytes"
	"testing"

	"petravault/internal/crypto"
)

// fastParams keeps unit tests quick; only the DefaultParams test below pays
// the full OWASP cost.
func fastParams() crypto.Params {
	return crypto.Params{Time: 1, Memory: 1024, Threads: 1}
}

func TestDefaultParamsValid(t *testing.T) {
	params := crypto.DefaultParams()
	if err := params.Validate(); err != nil {
		t.Fatalf("DefaultParams invalid: %v", err)
	}
	kek, err := crypto.DeriveKEK([]byte("password"), bytes.Repeat([]byte{0xA5}, 16), params)
	if err != nil {
		t.Fatal(err)
	}
	again, err := crypto.DeriveKEK([]byte("password"), bytes.Repeat([]byte{0xA5}, 16), params)
	if err != nil {
		t.Fatal(err)
	}
	if !kek.Equal(again) {
		t.Fatal("DefaultParams derivation is not deterministic")
	}
}

func TestDeriveKEKDeterministic(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{0xA5}, 16)
	first, err := crypto.DeriveKEK([]byte("correct horse"), salt, fastParams())
	if err != nil {
		t.Fatal(err)
	}
	second, err := crypto.DeriveKEK([]byte("correct horse"), salt, fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("same password and salt derived different keys")
	}
}

func TestDeriveKEKSensitiveToInputs(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{0xA5}, 16)
	base, err := crypto.DeriveKEK([]byte("password"), salt, fastParams())
	if err != nil {
		t.Fatal(err)
	}
	otherSalt := bytes.Repeat([]byte{0xA5}, 24)
	otherSalt[0] ^= 0x01
	for _, tt := range []struct {
		name     string
		password []byte
		salt     []byte
		params   crypto.Params
	}{
		{name: "password", password: []byte("Password"), salt: salt, params: fastParams()},
		{name: "salt", password: []byte("password"), salt: otherSalt, params: fastParams()},
		{name: "time", password: []byte("password"), salt: salt, params: crypto.Params{Time: 2, Memory: 1024, Threads: 1}},
		{name: "memory", password: []byte("password"), salt: salt, params: crypto.Params{Time: 1, Memory: 2048, Threads: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := crypto.DeriveKEK(tt.password, tt.salt, tt.params)
			if err != nil {
				t.Fatal(err)
			}
			if base.Equal(got) {
				t.Fatalf("different %s derived the same key", tt.name)
			}
		})
	}
}

func TestDeriveKEKRejectsBadInputs(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{0xA5}, 16)
	for _, tt := range []struct {
		name     string
		password []byte
		salt     []byte
		params   crypto.Params
	}{
		{name: "empty password", password: nil, salt: salt, params: fastParams()},
		{name: "short salt", password: []byte("password"), salt: bytes.Repeat([]byte{0xA5}, 8), params: fastParams()},
		{name: "zero time", password: []byte("password"), salt: salt, params: crypto.Params{Time: 0, Memory: 1024, Threads: 1}},
		{name: "absurd time", password: []byte("password"), salt: salt, params: crypto.Params{Time: 64, Memory: 1024, Threads: 1}},
		{name: "tiny memory", password: []byte("password"), salt: salt, params: crypto.Params{Time: 1, Memory: 512, Threads: 1}},
		{name: "absurd memory", password: []byte("password"), salt: salt, params: crypto.Params{Time: 1, Memory: 1 << 24, Threads: 1}},
		{name: "zero threads", password: []byte("password"), salt: salt, params: crypto.Params{Time: 1, Memory: 1024, Threads: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := crypto.DeriveKEK(tt.password, tt.salt, tt.params); err == nil {
				t.Fatalf("DeriveKEK accepted %s, want rejection", tt.name)
			}
		})
	}
}

func TestValidateMemoryCap(t *testing.T) {
	t.Parallel()

	if err := (crypto.Params{Time: 1, Memory: 256 << 10, Threads: 1}).Validate(); err != nil {
		t.Fatalf("Validate rejected 256 MiB, want acceptance: %v", err)
	}
	if err := (crypto.Params{Time: 1, Memory: (256 << 10) + 1, Threads: 1}).Validate(); err == nil {
		t.Fatal("Validate accepted memory above 256 MiB, want rejection")
	}
}

func TestRandomSalt(t *testing.T) {
	t.Parallel()

	first, err := crypto.RandomSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != crypto.SaltLength {
		t.Fatalf("salt length = %d, want %d", len(first), crypto.SaltLength)
	}
	second, err := crypto.RandomSalt()
	if err != nil {
		t.Fatal(err)
	}
	same := true
	for i := range first {
		if first[i] != second[i] {
			same = false
		}
	}
	if same {
		t.Fatal("two random salts are identical")
	}
}
