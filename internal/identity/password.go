// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/term"
)

// maxPasswordFileSize bounds password-file reads.
const maxPasswordFileSize = 65536

// ReadPassword returns the keystore password, in order of preference
// (DESIGN.md §11.2): PETRAVAULT_PASSWORD_COMMAND, PETRAVAULT_PASSWORD_FILE
// (which must be mode 0600), or an interactive prompt. Passwords never come
// from flags, config files, or job files, and never appear in errors or logs.
func ReadPassword(ctx context.Context, prompt string) ([]byte, error) {
	if cmd, ok := os.LookupEnv("PETRAVAULT_PASSWORD_COMMAND"); ok && cmd != "" {
		return passwordFromCommand(ctx, cmd)
	}
	if path, ok := os.LookupEnv("PETRAVAULT_PASSWORD_FILE"); ok && path != "" {
		return passwordFromFile(path)
	}
	return passwordFromPrompt(prompt)
}

// ReadPasswordConfirm is ReadPassword, except an interactive prompt asks
// twice and the two entries must match. Helpers from the environment are
// used once without confirmation.
func ReadPasswordConfirm(ctx context.Context, prompt, confirmPrompt string) ([]byte, error) {
	if cmd, ok := os.LookupEnv("PETRAVAULT_PASSWORD_COMMAND"); ok && cmd != "" {
		return passwordFromCommand(ctx, cmd)
	}
	if path, ok := os.LookupEnv("PETRAVAULT_PASSWORD_FILE"); ok && path != "" {
		return passwordFromFile(path)
	}
	first, err := passwordFromPrompt(prompt)
	if err != nil {
		return nil, err
	}
	second, err := passwordFromPrompt(confirmPrompt)
	if err != nil {
		clear(first)
		return nil, err
	}
	defer clear(second)
	if len(first) == 0 || subtle.ConstantTimeCompare(first, second) != 1 {
		clear(first)
		return nil, errors.New("passwords do not match")
	}
	return first, nil
}

func passwordFromCommand(ctx context.Context, cmdStr string) ([]byte, error) {
	//nolint:gosec // the helper command comes from the operator's own
	// PETRAVAULT_PASSWORD_COMMAND (DESIGN.md §11.2), not from untrusted input.
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run password command: %w", err)
	}
	pw := bytes.Clone(bytes.TrimRight(out, "\r\n"))
	clear(out)
	if len(pw) == 0 {
		return nil, errors.New("password command produced no output")
	}
	return pw, nil
}

func passwordFromFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat password file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("password file %s: permissions %v too open, want 0600", path, fi.Mode().Perm())
	}
	if fi.Size() > maxPasswordFileSize {
		return nil, fmt.Errorf("password file %s too large", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password file: %w", err)
	}
	pw := bytes.Clone(bytes.TrimRight(data, "\r\n"))
	clear(data)
	if len(pw) == 0 {
		return nil, fmt.Errorf("password file %s is empty", path)
	}
	return pw, nil
}

func passwordFromPrompt(prompt string) ([]byte, error) {
	if prompt == "" {
		prompt = "Enter password: "
	}
	fmt.Fprint(os.Stderr, prompt)
	var pw []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprint(os.Stderr, "\n")
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		pw = bytes.Clone(raw)
		clear(raw)
	} else {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			return nil, fmt.Errorf("read password: %w", err)
		}
		pw = bytes.Clone(bytes.TrimRight(line, "\r\n"))
		clear(line)
	}
	if len(pw) == 0 {
		return nil, errors.New("password must not be empty")
	}
	return pw, nil
}
