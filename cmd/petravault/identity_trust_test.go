// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
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

func TestTerminalIdentityMetadataIsQuoted(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	name := "mallory\x1b[2J\nforged-row"
	out, _ := runCmd(t, "identity", "create", "--name", name)
	fp := fingerprintFromCreate(t, out)

	for _, args := range [][]string{{"identity", "list"}, {"trust", "list"}} {
		out, _ = runCmd(t, args...)
		if strings.Contains(out, "\x1b") || strings.Contains(out, "\nforged-row") {
			t.Fatalf("%v emitted raw terminal metadata: %q", args, out)
		}
		if !strings.Contains(out, `mallory\x1b[2J\nforged-row`) {
			t.Fatalf("%v did not quote the identity name: %q", args, out)
		}
	}

	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	out, _ = runCmd(t, "--repository", repo, "trust", "sync")
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\nforged-row") {
		t.Fatalf("trust sync emitted raw advisory metadata: %q", out)
	}
	if !strings.Contains(out, `mallory\x1b[2J\nforged-row`) {
		t.Fatalf("trust sync did not quote the advisory identity name: %q", out)
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

func TestConfigSignerRevokedRefusesOpen(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)
	repo := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", repo, "--identity", fp, "--ecc", "off")
	// Control: the config opens while its signer is trusted.
	runCmd(t, "-r", repo, "info")
	runCmd(t, "trust", "revoke", fp, "--reason", "key rotation test")
	err := runCmdErr(t, "-r", repo, "info")
	if err == nil {
		t.Fatal("info opened a config signed by a revoked key, want refusal")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("revoked config error = %v, want an untrusted-signer failure", err)
	}
	if !strings.Contains(err.Error(), "`ecc set` cannot recover") {
		t.Fatalf("revoked config error = %v, want accurate recovery guidance", err)
	}
	err = runCmdErr(t, "-r", repo, "ecc", "set", "high")
	if !errors.Is(err, pverrors.ErrUntrustedSigner) || !strings.Contains(err.Error(), "cannot recover") {
		t.Fatalf("ecc set error = %v, want fail-closed recovery refusal", err)
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
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")

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
	if err := runCmdErr(t, "--repository", missing, "trust", "add", fp, "--grant-access"); err == nil {
		t.Fatal("trust add --grant-access succeeded without a repository")
	}
	if err := runCmdErr(t, "trust", "add", fp, "--grant-read"); err == nil {
		t.Fatal("removed --grant-read flag still accepted")
	}
}

func TestIdentityImportTrustFlag(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	pubFile := filepath.Join(t.TempDir(), "alice.pub")
	runCmd(t, "identity", "export", fp, "--output", pubFile)

	// Fresh client, default import: trusted list stays empty (fail closed).
	isolatedIdentityEnv(t, "other-password")
	runCmd(t, "identity", "import", pubFile)
	out, _ = runCmd(t, "trust", "list")
	if strings.Contains(out, "alice") {
		t.Fatalf("trust list after plain import = %q, want no trusted identities", out)
	}

	// Fresh client, import --trust: self-trusted in one step.
	isolatedIdentityEnv(t, "third-password")
	runCmd(t, "identity", "import", pubFile, "--trust")
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("trust list after import --trust = %q, want alice", out)
	}
}

func TestTrustPublishRecover(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")
	runCmd(t, "trust", "revoke", bobFP, "--reason", "left", "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "publish")

	// Lose the local trust store, keep the keys, then recover.
	trustRoot := trustDir()
	if err := os.RemoveAll(trustRoot); err != nil {
		t.Fatal(err)
	}
	out, _ := runCmd(t, "trust", "list")
	if strings.Contains(out, "alice") || strings.Contains(out, "bob") {
		t.Fatalf("trust list after wipe = %q, want empty", out)
	}
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "recover")
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("trust list after recover = %q, want alice", out)
	}
	if !strings.Contains(out, "(revoked)") {
		t.Fatalf("trust list after recover = %q, want bob revoked", out)
	}
}

func TestTrustSyncFromRepoCopy(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")

	// Forget bob locally; the repo still holds his advisory copy.
	runCmd(t, "trust", "remove", bobFP)
	out, _ := runCmd(t, "--repository", root, "trust", "sync")
	if !strings.Contains(out, "bob") || !strings.Contains(out, "untrusted") {
		t.Fatalf("trust sync list = %q, want bob untrusted", out)
	}
	runCmd(t, "--repository", root, "trust", "sync", bobFP)
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "bob") {
		t.Fatalf("trust list after sync = %q, want bob", out)
	}
}

func TestTrustGrantAccessFlag(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")

	if got := countSuffix(t, filepath.Join(root, "keys"), ".slot"); got != 2 {
		t.Fatalf("keys dir holds %d slots, want alice plus bob", got)
	}
}

func TestMembersPublishSyncOnboards(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")
	runCmd(t, "--identity", aliceFP, "--repository", root, "members", "publish")

	// Fresh trust store holding only the granter: one check, rest follows.
	if err := os.RemoveAll(trustDir()); err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(t.TempDir(), "alice.pub")
	runCmd(t, "identity", "export", aliceFP, "--output", pubFile)
	runCmd(t, "identity", "import", pubFile, "--trust")
	out, _ := runCmd(t, "--identity", bobFP, "--repository", root, "members", "sync")
	if !strings.Contains(out, "adopted 1 new members") {
		t.Fatalf("members sync output = %q, want 1 adoption (bob)", out)
	}
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "bob") {
		t.Fatalf("trust list after sync = %q, want bob", out)
	}
}

func TestMembersSyncUntrustedHints(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	aliceOut, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, aliceOut)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)
	charlieOut, _ := runCmd(t, "identity", "create", "--name", "charlie")
	charlieFP := fingerprintFromCreate(t, charlieOut)

	root := filepath.Join(t.TempDir(), "repo")
	runCmd(t, "init", root, "--identity", aliceFP)
	runCmd(t, "--identity", aliceFP, "--repository", root, "trust", "add", bobFP, "--grant-access")
	// Bob (not Alice) grants Charlie, so the slot stage names Bob.
	runCmd(t, "--identity", bobFP, "--repository", root, "trust", "add", charlieFP, "--grant-access")
	runCmd(t, "--identity", aliceFP, "--repository", root, "members", "publish")

	// New machine holding only Charlie's private key: wipe the trust store,
	// keep the keystore, self-trust only.
	pubFile := filepath.Join(t.TempDir(), "charlie.pub")
	runCmd(t, "identity", "export", charlieFP, "--output", pubFile)
	if err := os.RemoveAll(trustDir()); err != nil {
		t.Fatal(err)
	}
	runCmd(t, "identity", "import", pubFile, "--trust")

	// Stage 1: repository config names no trusted key. The hint must name
	// the discovery command while staying exit 4.
	err := runCmdErr(t, "--identity", charlieFP, "--repository", root, "members", "sync")
	if err == nil {
		t.Fatal("members sync without any granter trusted succeeded, want hint error")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("members sync error = %v, want ErrUntrustedSigner", err)
	}
	if pverrors.ExitCode(err) != pverrors.ExitIntegrity {
		t.Fatalf("members sync exit = %d, want %d", pverrors.ExitCode(err), pverrors.ExitIntegrity)
	}
	if !strings.Contains(err.Error(), "trust sync") {
		t.Fatalf("members sync error = %q, want trust-sync hint", err.Error())
	}

	// Stage 2: Alice trusted resolves the config, but Charlie's slot was
	// granted by Bob. The hint must name Bob's fingerprint.
	runCmd(t, "--repository", root, "trust", "sync", aliceFP)
	err = runCmdErr(t, "--identity", charlieFP, "--repository", root, "members", "sync")
	if err == nil {
		t.Fatal("members sync trusting only Alice succeeded, want slot-granter hint")
	}
	if !errors.Is(err, pverrors.ErrUntrustedSigner) {
		t.Fatalf("members sync error = %v, want ErrUntrustedSigner", err)
	}
	if !strings.Contains(err.Error(), bobFP) {
		t.Fatalf("members sync error = %q, want slot granter %s", err.Error(), bobFP)
	}
	if !strings.Contains(err.Error(), "trust sync") {
		t.Fatalf("members sync error = %q, want trust-sync hint", err.Error())
	}

	// Stage 3: trusting Bob as well completes the onboarding.
	runCmd(t, "--repository", root, "trust", "sync", bobFP)
	out, _ := runCmd(t, "--identity", charlieFP, "--repository", root, "members", "sync")
	if !strings.Contains(out, "adopted") {
		t.Fatalf("members sync output = %q, want adoption", out)
	}
}
