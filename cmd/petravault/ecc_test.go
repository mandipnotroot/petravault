// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestECCSetAndRebuild(t *testing.T) {
	isolatedIdentityEnv(t, "test-password")

	out, _ := runCmd(t, "identity", "create", "--name", "alice")
	fp := fingerprintFromCreate(t, out)

	root := filepath.Join(t.TempDir(), "repo")
	out, _ = runCmd(t, "init", root, "--identity", fp, "--ecc", "high")
	if !strings.Contains(out, "k=20") || !strings.Contains(out, "m=3") {
		t.Fatalf("init output = %q, want high profile k=20 m=3", out)
	}

	out, _ = runCmd(t, "--repository", root, "info")
	if !strings.Contains(out, "high") || !strings.Contains(out, "k=20") {
		t.Fatalf("info output = %q, want ecc high", out)
	}

	out, _ = runCmd(t, "--repository", root, "ecc", "set", "low")
	if !strings.Contains(out, "k=50") || !strings.Contains(out, "m=1") {
		t.Fatalf("ecc set output = %q, want low profile k=50 m=1", out)
	}

	out, _ = runCmd(t, "--repository", root, "info")
	if !strings.Contains(out, "low") {
		t.Fatalf("info after set = %q, want ecc low", out)
	}

	// No packs yet: rebuild is a no-op success.
	runCmd(t, "--repository", root, "ecc", "rebuild")

	if err := runCmdErr(t, "--repository", root, "ecc", "set", "bogus"); err == nil {
		t.Fatal("ecc set accepted a bogus profile, want failure")
	}
	if err := runCmdErr(t, "--repository", root, "ecc", "set", "0.1%"); err == nil {
		t.Fatal("ecc set accepted an out-of-range percentage, want failure")
	}
}
