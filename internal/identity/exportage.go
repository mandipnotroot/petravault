// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"fmt"
	"time"
)

// ExportStaleAfter is the age after which adopted trust data warns loudly
// (DESIGN.md §5.2): a stale record misses recent additions (safe direction:
// unknown signers fail closed) and recent revocations (unsafe direction:
// re-confirm with the team). Staleness never fails the command: offline
// recovery must keep working without a trusted clock, and a hostile
// repository can only replay genuinely published data, never forge it.
const ExportStaleAfter = 30 * 24 * time.Hour

// ExportAgeWarning describes the staleness of trust data exported at
// exportedAt as seen at now (nil means time.Now). It returns "" when the
// data is fresh. A zero export time warns as unknown age; timestamps in the
// future are treated as fresh (clock skew) since callers print the date
// itself alongside any warning.
func ExportAgeWarning(exportedAt time.Time, now func() time.Time) string {
	if now == nil {
		now = time.Now
	}
	if exportedAt.IsZero() {
		return "trust data has no export time; re-confirm revocations with your team"
	}
	at := now().UTC()
	age := at.Sub(exportedAt.UTC())
	if age <= ExportStaleAfter {
		return ""
	}
	days := int(age.Hours() / 24)
	return fmt.Sprintf("trust data is %d days old (published %s); re-confirm revocations with your team",
		days, exportedAt.UTC().Format("2006-01-02"))
}
