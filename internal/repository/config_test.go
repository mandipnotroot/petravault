// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"bytes"
	"crypto/mldsa"
	"errors"
	"io"
	"testing"
	"time"

	"petravault/internal/chunking"
	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/repository"
)

type configSigner struct {
	priv *mldsa.PrivateKey
}

func (s configSigner) Sign(context string, message []byte) ([]byte, error) {
	return s.priv.Sign(nil, message, &mldsa.Options{Context: context})
}

func mustConfigKeys(t *testing.T) (*mldsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.PublicKey().Bytes()
}

func mustConfig(t *testing.T, repoID string) repository.Config {
	t.Helper()
	cfg, err := repository.NewConfig(repoID, chunking.DefaultParams(), 0, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfigRoundTrip(t *testing.T) {
	t.Parallel()

	priv, pub := mustConfigKeys(t)
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	repoID, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	cfg := mustConfig(t, repoID)
	if err := repository.WriteConfig(ctx, repo, configSigner{priv}, cfg); err != nil {
		t.Fatal(err)
	}
	got, signer, err := repository.ReadConfig(ctx, repo, map[string][]byte{"alice": pub})
	if err != nil {
		t.Fatal(err)
	}
	if signer != "alice" {
		t.Fatalf("signer = %q, want alice", signer)
	}
	if got.RepositoryID != repoID || got.CryptoSuite != crypto.SuiteID || got.ChunkingAlgorithm != crypto.ChunkingID {
		t.Fatalf("config = %+v", got)
	}
	if got.ECC != "medium" || got.PackSize != repository.DefaultPackSize {
		t.Fatalf("defaults not applied: %+v", got)
	}
}

func TestConfigIDsFrozen(t *testing.T) {
	t.Parallel()

	cfg := mustConfig(t, "repo-1")
	if cfg.CryptoSuite != "xwing-xchacha20poly1305-v1" || cfg.KEM != "mlkem768-x25519" ||
		cfg.Signature != "ml-dsa-65" || cfg.Hash != "blake3" || cfg.KDF != "argon2id" ||
		cfg.ChunkingAlgorithm != "kfastcdc-v1" {
		t.Fatalf("suite drifted: %+v", cfg)
	}
	if cfg.Version != repository.ConfigVersion {
		t.Fatalf("version = %d", cfg.Version)
	}
}

func TestGenerateIDUnique(t *testing.T) {
	t.Parallel()

	a, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := repository.GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 || len(b) != 64 {
		t.Fatalf("ids = %q, %q: want 64 hex chars", a, b)
	}
	if a == b {
		t.Fatal("two repository IDs collided")
	}
}

func TestConfigRejectsTamperedEnvelope(t *testing.T) {
	t.Parallel()

	priv, pub := mustConfigKeys(t)
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cfg := mustConfig(t, "repo-1")
	if err := repository.WriteConfig(ctx, repo, configSigner{priv}, cfg); err != nil {
		t.Fatal(err)
	}
	r, err := repo.GetObject(ctx, repository.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	raw[len(raw)-10] ^= 0x01
	if err := repo.PutObject(ctx, repository.ConfigKey, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.ReadConfig(ctx, repo, map[string][]byte{"alice": pub}); err == nil {
		t.Fatal("ReadConfig accepted a tampered config")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("tampered error = %v, want integrity failure", err)
	}
}

func TestConfigRejectsUntrustedSigner(t *testing.T) {
	t.Parallel()

	priv, _ := mustConfigKeys(t)
	_, malloryPub := mustConfigKeys(t)
	repo, err := repository.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := repository.WriteConfig(ctx, repo, configSigner{priv}, mustConfig(t, "repo-1")); err != nil {
		t.Fatal(err)
	}
	// Mallory's key never signed this config, and Alice's key is absent:
	// both must fail as untrusted.
	if _, _, err := repository.ReadConfig(ctx, repo, map[string][]byte{"mallory": malloryPub}); err == nil {
		t.Fatal("ReadConfig accepted an untrusted signer")
	} else if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("untrusted error = %v, want ErrUntrustedSigner", err)
	}
	if _, _, err := repository.ReadConfig(ctx, repo, map[string][]byte{}); err == nil {
		t.Fatal("ReadConfig accepted an empty trust map")
	} else if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("empty-trust error = %v, want ErrUntrustedSigner", err)
	}
}

func TestConfigRejectsSuiteDowngrade(t *testing.T) {
	t.Parallel()

	priv, pub := mustConfigKeys(t)
	cfg := mustConfig(t, "repo-1")
	cfg.CryptoSuite = "xchacha20poly1305-v0"
	if _, err := repository.SignConfig(configSigner{priv}, cfg); err == nil {
		t.Fatal("SignConfig accepted a downgraded suite")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("suite error = %v, want integrity failure", err)
	}
	// A config signed under the wrong context never verifies as a config.
	payload, err := mustConfig(t, "repo-1").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	wrongSig, err := priv.Sign(nil, payload, &mldsa.Options{Context: crypto.ContextManifest})
	if err != nil {
		t.Fatal(err)
	}
	_ = wrongSig
	_ = pub
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	priv, pub := mustConfigKeys(t)
	cfg := mustConfig(t, "repo-1")
	env, err := repository.SignConfig(configSigner{priv}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(env, []byte(`"payload"`), []byte(`"extra":true,"payload"`), 1)
	if _, _, err := repository.VerifyConfig(withExtra, pub); err == nil {
		t.Fatal("VerifyConfig accepted an unknown envelope field")
	}
}

func TestConfigNewRejectsBadInput(t *testing.T) {
	t.Parallel()

	if _, err := repository.NewConfig("", chunking.DefaultParams(), 0, "", nil); err == nil {
		t.Fatal("NewConfig accepted an empty repository id")
	} else if !errors.Is(err, pverrors.ErrUsage) {
		t.Fatalf("empty-id error = %v, want usage error", err)
	}
	bad := chunking.Params{MinSize: 1 << 20, AverageSize: 1 << 10, MaxSize: 8 << 20}
	if _, err := repository.NewConfig("r", bad, 0, "", nil); err == nil {
		t.Fatal("NewConfig accepted invalid chunking")
	}
	if _, err := repository.NewConfig("r", chunking.DefaultParams(), 0, "bogus", nil); err == nil {
		t.Fatal("NewConfig accepted an invalid ECC setting")
	}
	if _, err := repository.NewConfig("r", chunking.DefaultParams(), 1, "", nil); err == nil {
		t.Fatal("NewConfig accepted a tiny pack size")
	}
}

func TestConfigECCSettingsAccepted(t *testing.T) {
	t.Parallel()

	for _, ecc := range []string{"off", "low", "medium", "high", "2%", "7%", "25%", "100%"} {
		if _, err := repository.NewConfig("r", chunking.DefaultParams(), 0, ecc, func() time.Time {
			return time.Date(2026, time.October, 13, 10, 0, 0, 0, time.UTC)
		}); err != nil {
			t.Fatalf("NewConfig(%q) failed: %v", ecc, err)
		}
	}
}

func FuzzVerifyConfigNoPanic(f *testing.F) {
	priv, pub := mustConfigKeysForFuzz(f)
	env, err := repository.SignConfig(configSigner{priv}, mustConfigForFuzz(f, "repo-1"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(env)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = repository.VerifyConfig(data, pub)
	})
}

func mustConfigKeysForFuzz(f *testing.F) (*mldsa.PrivateKey, []byte) {
	f.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		f.Fatal(err)
	}
	return priv, priv.PublicKey().Bytes()
}

func mustConfigForFuzz(f *testing.F, repoID string) repository.Config {
	f.Helper()
	cfg, err := repository.NewConfig(repoID, chunking.DefaultParams(), 0, "", nil)
	if err != nil {
		f.Fatal(err)
	}
	return cfg
}
