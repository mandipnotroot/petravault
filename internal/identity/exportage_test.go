// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity_test

import (
	"strings"
	"testing"
	"time"

	"petravault/internal/identity"
)

func TestExportAgeWarning(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	at := func() time.Time { return now }
	for _, tt := range []struct {
		name     string
		exported time.Time
		wantWarn bool
		wantText string
	}{
		{name: "fresh", exported: now.Add(-24 * time.Hour)},
		{name: "boundary", exported: now.Add(-identity.ExportStaleAfter)},
		{name: "stale", exported: now.Add(-31 * 24 * time.Hour), wantWarn: true, wantText: "31 days old"},
		{name: "future skew", exported: now.Add(time.Hour)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := identity.ExportAgeWarning(tt.exported, at)
			if !tt.wantWarn && got != "" {
				t.Fatalf("warning = %q, want none", got)
			}
			if tt.wantWarn {
				if got == "" {
					t.Fatal("missing staleness warning, want one")
				}
				if !strings.Contains(got, tt.wantText) {
					t.Fatalf("warning = %q, want it to contain %q", got, tt.wantText)
				}
				if !strings.Contains(got, "re-confirm revocations") {
					t.Fatalf("warning = %q, want re-confirm guidance", got)
				}
			}
		})
	}
}

func TestExportAgeWarningZeroTime(t *testing.T) {
	t.Parallel()

	got := identity.ExportAgeWarning(time.Time{}, nil)
	if got == "" {
		t.Fatal("missing warning for unknown export time, want one")
	}
}
