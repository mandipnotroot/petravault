// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"petravault/internal/identity"
)

func TestPasswordFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "")
	t.Setenv("PETRAVAULT_PASSWORD_FILE", path)
	pw, err := identity.ReadPassword(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pw)
	if string(pw) != "s3cret" {
		t.Fatalf("password = %q, want s3cret", pw)
	}
}

func TestPasswordFileModeRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "")
	t.Setenv("PETRAVAULT_PASSWORD_FILE", path)
	if _, err := identity.ReadPassword(t.Context(), ""); err == nil {
		t.Fatal("ReadPassword accepted a group-readable password file")
	}
}

func TestPasswordCommandRoundTrip(t *testing.T) {
	t.Setenv("PETRAVAULT_PASSWORD_FILE", "")
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "printf s3cret")
	pw, err := identity.ReadPassword(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pw)
	if string(pw) != "s3cret" {
		t.Fatalf("password = %q, want s3cret", pw)
	}
}

func TestPasswordCommandEmptyRefused(t *testing.T) {
	t.Setenv("PETRAVAULT_PASSWORD_FILE", "")
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "printf ''")
	if _, err := identity.ReadPassword(t.Context(), ""); err == nil {
		t.Fatal("ReadPassword accepted empty command output")
	}
}

func TestPasswordNeverInError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PETRAVAULT_PASSWORD_COMMAND", "")
	t.Setenv("PETRAVAULT_PASSWORD_FILE", path)
	_, err := identity.ReadPassword(t.Context(), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); len(got) > 0 && containsSecret(got, "s3cret") {
		t.Fatal("error contains the password")
	}
}

func containsSecret(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
