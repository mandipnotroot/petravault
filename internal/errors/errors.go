// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package errors defines the process exit codes and sentinel errors used
// across Petravault (DESIGN.md §16, GO_GUIDELINES.md §9).
package errors

import (
	"errors"
	"fmt"
)

// Process exit codes (DESIGN.md §16).
const (
	ExitOK        = 0
	ExitError     = 1
	ExitUsage     = 2
	ExitWarnings  = 3
	ExitIntegrity = 4
)

var (
	ErrUsage     = errors.New("usage error")
	ErrWarnings  = errors.New("completed with warnings")
	ErrIntegrity = errors.New("integrity or trust failure")

	// Specific integrity failures wrap ErrIntegrity (exit code 4).
	ErrAuthFailed      = fmt.Errorf("%w: authentication failed", ErrIntegrity)
	ErrBadSignature    = fmt.Errorf("%w: invalid signature", ErrIntegrity)
	ErrUntrustedSigner = fmt.Errorf("%w: signer is not in the trust list", ErrIntegrity)
	ErrRollback        = fmt.Errorf("%w: rollback detected", ErrIntegrity)
	ErrUnrecoverable   = fmt.Errorf("%w: damage exceeds the parity budget", ErrIntegrity)
)

// ExitCode maps an error to the process exit code. Integrity wins over warnings.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrIntegrity):
		return ExitIntegrity
	case errors.Is(err, ErrUsage):
		return ExitUsage
	case errors.Is(err, ErrWarnings):
		return ExitWarnings
	default:
		return ExitError
	}
}
