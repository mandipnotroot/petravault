// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryExportImport(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")
	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	aliceFP := fingerprintFromCreate(t, out)
	bobOut, _ := runCmd(t, "identity", "create", "--name", "bob")
	bobFP := fingerprintFromCreate(t, bobOut)
	runCmd(t, "trust", "revoke", bobFP, "--reason", "left", "--identity", aliceFP)

	bundle := filepath.Join(t.TempDir(), "alice.recovery")
	runCmd(t, "recovery", "export", "--output", bundle, "--identity", aliceFP)
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("export did not write bundle: %v", err)
	}

	// Wipe client state, keep nothing, then restore from the bundle.
	if err := os.RemoveAll(keystoreDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(trustDir()); err != nil {
		t.Fatal(err)
	}
	runCmd(t, "recovery", "import", bundle, "--identity", aliceFP)
	out, _ = runCmd(t, "identity", "list")
	if !strings.Contains(out, "alice") {
		t.Fatalf("identity list after import = %q, want alice", out)
	}
	out, _ = runCmd(t, "trust", "list")
	if !strings.Contains(out, "alice") || !strings.Contains(out, "(revoked)") {
		t.Fatalf("trust list after import = %q, want alice and bob revoked", out)
	}
	out, _ = runCmd(t, "recovery", "status", bundle)
	if !strings.Contains(out, "bundle exported") {
		t.Fatalf("recovery status output = %q, want export time", out)
	}
}
