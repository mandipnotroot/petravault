// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package errors_test

import (
	"errors"
	"fmt"
	"testing"

	pverrors "petravault/internal/errors"
)

func TestExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: pverrors.ExitOK},
		{name: "integrity", err: pverrors.ErrIntegrity, want: pverrors.ExitIntegrity},
		{name: "wrapped integrity", err: fmt.Errorf("verify: %w", pverrors.ErrBadSignature), want: pverrors.ExitIntegrity},
		{name: "usage", err: pverrors.ErrUsage, want: pverrors.ExitUsage},
		{name: "warnings", err: pverrors.ErrWarnings, want: pverrors.ExitWarnings},
		{name: "generic", err: errors.New("boom"), want: pverrors.ExitError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pverrors.ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestIntegrityWinsOverWarnings(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("%w: %w", pverrors.ErrWarnings, pverrors.ErrRollback)
	if got := pverrors.ExitCode(err); got != pverrors.ExitIntegrity {
		t.Fatalf("ExitCode = %d, want %d", got, pverrors.ExitIntegrity)
	}
}
