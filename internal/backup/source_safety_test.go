// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceSubstitutionBeforeOpen(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		name := "leaf"
		if ancestor {
			name = "ancestor"
		}
		t.Run(name, func(t *testing.T) {
			source := t.TempDir()
			outside := t.TempDir()
			if err := os.Mkdir(filepath.Join(source, "dir"), 0o700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(source, "dir", "file")
			if err := os.WriteFile(file, []byte("selected dummy content"), 0o600); err != nil {
				t.Fatal(err)
			}
			expected, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside dummy content"), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(source)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if ancestor {
				if err := os.Rename(filepath.Join(source, "dir"), filepath.Join(source, "old-dir")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(source, "dir")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			} else {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "file"), file); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			b := runner{sourceRoot: root}
			if chunks, added, err := b.chunkFile(t.Context(), "dir/file", expected); err == nil || len(chunks) != 0 || len(added) != 0 {
				t.Fatalf("substitution was consumed: chunks=%v added=%v err=%v", chunks, added, err)
			}
		})
	}
}
