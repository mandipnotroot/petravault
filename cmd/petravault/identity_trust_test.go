// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"petravault/internal/crypto"
	"petravault/internal/identity"
	"petravault/internal/repository"
)

func isolatedIdentityEnv(t *testing.T, password string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("PETRAVAULT_CONFIG", "")
	t.Setenv("PETRAVAULT_REPOSITORY", "")
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PETRAVAULT_PASSWORD_FILE", pwFile)
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "")
}

func runCmd(t *testing.T, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run %v failed: %v (stderr: %s)", args, err, stderr.String())
	}
	return stdout.String(), stderr.String()
}

func runCmdErr(t *testing.T, args ...string) error {
	t.Helper()
	var stdout, stderr bytes.Buffer
	return run(context.Background(), args, &stdout, &stderr)
}

func fingerprintFromCreate(t *testing.T, output string) string {
	t.Helper()
	for line := range strings.Lines(output) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "fingerprint:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no fingerprint in output %q", output)
	return ""
}

func TestIdentityCreateList(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	out, _ = runCmd(t, "identity", "list")
	if !strings.Contains(out, "alice") || !strings.Contains(out, fp) {
		t.Fatalf("list output = %q, want alice and fingerprint", out)
	}
}

func TestIdentityExportImport(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	pubFile := filepath.Join(t.TempDir(), "alice.pub")
	runCmd(t, "identity", "export", fp, "--output", pubFile)
	if _, err := os.Stat(pubFile); err != nil {
		t.Fatalf("export did not write file: %v", err)
	}

	// Import into a fresh keystore as a second client would.
	isolatedIdentityEnv(t, "other-password")
	runCmd(t, "identity", "import", pubFile)
	out, _ = runCmd(t, "identity", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("imported list = %q, want alice", out)
	}
}

func TestTrustAddListRemove(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	// identity create auto-trusts; list shows it.
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("trust list = %q, want alice", out)
	}
	runCmd(t, "trust", "remove", fp)
	out, _ = runCmd(t, "trust", "list")
	if strings.Contains(out, "alice") {
		t.Fatalf("trust list after remove = %q, want empty", out)
	}
	// Re-add via --from after export.
	pubFile := filepath.Join(t.TempDir(), "alice.pub")
	runCmd(t, "identity", "export", fp, "--output", pubFile)
	if err := runCmdErr(t, "trust", "remove", fp); err == nil {
		t.Fatal("second trust remove succeeded, want not-trusted error")
	}
	runCmd(t, "trust", "add", fp, "--from", pubFile)
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("trust list after re-add = %q, want alice", out)
	}
}

func TestTrustAddRejectsMismatch(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, out)
	out, _ = runCmd(t, "identity", "create", "--name", "mallory")
	malloryFP := fingerprintFromCreate(t, out)

	pubFile := filepath.Join(t.TempDir(), "mallory.pub")
	runCmd(t, "identity", "export", malloryFP, "--output", pubFile)
	// Present Mallory's keys under Alice's fingerprint: must fail.
	if err := runCmdErr(t, "trust", "add", aliceFP, "--from", pubFile); err == nil {
		t.Fatal("trust add accepted a fingerprint mismatch")
	}
}

func TestTrustRevokeSelf(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	runCmd(t, "trust", "revoke", fp, "--reason", "lost laptop")
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "(revoked)") {
		t.Fatalf("trust list = %q, want revoked marker", out)
	}
}

func TestTrustRevokeByOtherSigner(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	runCmd(t, "trust", "revoke", aliceFP, "--reason", "compromised", "--identity", bobFP)
	out, _ := runCmd(t, "trust", "list")
	if !strings.Contains(out, "(revoked)") {
		t.Fatalf("trust list = %q, want alice revoked by bob", out)
	}
}

func TestTrustRevokeRequiresReason(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	if err := runCmdErr(t, "trust", "revoke", fp); err == nil {
		t.Fatal("revoke without --reason succeeded")
	}
}

func TestTrustGrantRead(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)

	// Alice grants Bob read access. Bob is already trusted locally from
	// creation; re-adding is idempotent and then seals the master key.
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-read")

	if got := countSuffix(t, filepath.Join(root, "keys"), ".slot"); got != 2 {
		t.Fatalf("keys dir holds %d slots, want alice plus bob", got)
	}
	if got := countSuffix(t, filepath.Join(root, "identities"), ".pub"); got != 2 {
		t.Fatalf("identities dir holds %d copies, want alice plus bob", got)
	}

	// Both slots open to the same master key.
	aliceParsed, err := identity.ParseFingerprint(aliceFP)
	if err != nil {
		t.Fatal(err)
	}
	bobParsed, err := identity.ParseFingerprint(bobFP)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(keystoreDir())
	alicePriv, err := store.LoadPrivate(aliceParsed, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := store.LoadPrivate(bobParsed, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.NewTrustStore(trustDir())
	trusted, err := trust.List()
	if err != nil {
		t.Fatal(err)
	}
	byFP := make(map[string][]byte, len(trusted))
	for _, id := range trusted {
		byFP[id.Fingerprint.String()] = id.SignPublic
	}
	repo := repository.NewLocal(root)
	ctx := context.Background()
	repoCfg, _, err := repository.ReadConfig(ctx, repo, byFP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(granter string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(granter)
		if err != nil {
			return nil, err
		}
		id, err := trust.TrustedPublic(fp)
		if err != nil {
			return nil, err
		}
		return id.SignPublic, nil
	}
	aliceMaster, err := openSlotForTest(t, root, repoCfg.RepositoryID, aliceParsed, alicePriv, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceMaster.Zero()
	bobMaster, err := openSlotForTest(t, root, repoCfg.RepositoryID, bobParsed, bobPriv, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer bobMaster.Zero()
	if !aliceMaster.Equal(bobMaster) {
		t.Fatal("alice and bob slots hold different master keys")
	}
}

func openSlotForTest(t *testing.T, root, repositoryID string, fp identity.Fingerprint, priv *identity.PrivateIdentity, lookup func(string) ([]byte, error)) (crypto.SecretKey, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, identity.SlotKey(fp)))
	if err != nil {
		return crypto.SecretKey{}, err
	}
	return identity.OpenSlotTrusted(raw, repositoryID, fp, priv.KEMPrivate(), lookup)
}

func TestTrustGrantReadRejectsUnknownRepository(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	missing := filepath.Join(t.TempDir(), "no-repo")
	if err := runCmdErr(t, "--repository", missing, "trust", "add", fp, "--grant-read"); err == nil {
		t.Fatal("trust add --grant-read succeeded without a repository")
	}
}
