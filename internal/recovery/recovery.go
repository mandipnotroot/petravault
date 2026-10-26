// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package recovery builds single-file client recovery bundles (DESIGN.md
// §5.2): one password-encrypted file holding an identity (public file plus
// the still-sealed private file) and the trust view. The bundle never holds
// decrypted key material — export copies sealed bytes — and import proves
// both passwords by unlocking: the bundle envelope, then the restored
// private key.
package recovery

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
)

// BundleVersion is the recovery bundle format version.
const BundleVersion = 1

// fileEntry carries one client file by its base name with raw bytes. Trust
// names are fingerprints with a fixed suffix. Names are validated on import
// and never trusted as paths.
type fileEntry struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// bundle is the sealed payload.
type bundle struct {
	Version       int         `json:"version"`
	ExportedAt    time.Time   `json:"exported_at"`
	Identity      string      `json:"identity"`
	Public        []byte      `json:"public"`
	PrivateSealed []byte      `json:"private_sealed"`
	Trusted       []fileEntry `json:"trusted"`
	Revoked       []fileEntry `json:"revoked"`
}

// ExportSummary reports what one export captured.
type ExportSummary struct {
	Owner      identity.Fingerprint
	Trusted    int
	Revoked    int
	ExportedAt time.Time
}

// ImportSummary reports what one import restored.
type ImportSummary struct {
	Owner      identity.Fingerprint
	Trusted    int
	Revoked    int
	ExportedAt time.Time
}

// Export captures fp's recovery bundle and seals it under bundlePassword.
// The private file is copied sealed; export never unlocks keys.
func Export(store *identity.Store, trust *identity.TrustStore, fp identity.Fingerprint, bundlePassword []byte, now func() time.Time) ([]byte, *ExportSummary, error) {
	if store == nil {
		return nil, nil, errors.New("export recovery: store is nil")
	}
	if trust == nil {
		return nil, nil, errors.New("export recovery: trust store is nil")
	}
	if now == nil {
		now = time.Now
	}
	id, err := store.LoadPublic(fp)
	if err != nil {
		return nil, nil, err
	}
	pub, err := identity.MarshalPublic(id)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := store.SealedPrivate(fp)
	if err != nil {
		return nil, nil, err
	}
	listed, err := trust.List()
	if err != nil {
		return nil, nil, err
	}
	out := bundle{
		Version:       BundleVersion,
		ExportedAt:    now().UTC(),
		Identity:      fp.String(),
		Public:        pub,
		PrivateSealed: sealed,
	}
	for _, entry := range listed {
		entryPub, err := identity.MarshalPublic(&entry)
		if err != nil {
			return nil, nil, err
		}
		out.Trusted = append(out.Trusted, fileEntry{Name: entry.Fingerprint.String() + ".json", Data: entryPub})
	}
	revocations, err := trust.RevocationEnvelopes()
	if err != nil {
		return nil, nil, err
	}
	for _, env := range revocations {
		rev, err := identity.DecodeRevocation(env)
		if err != nil {
			return nil, nil, err
		}
		out.Revoked = append(out.Revoked, fileEntry{Name: rev.Fingerprint.String() + ".rev", Data: env})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal recovery bundle: %w", err)
	}
	locked, err := crypto.Lock(bundlePassword, raw)
	clear(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("seal recovery bundle: %w", err)
	}
	return locked, &ExportSummary{
		Owner:      fp,
		Trusted:    len(out.Trusted),
		Revoked:    len(out.Revoked),
		ExportedAt: out.ExportedAt,
	}, nil
}

// Import opens a bundle under bundlePassword and restores it into store and
// trust, then proves identityPassword unlocks the restored private key. The
// bundle must name wantFP.
func Import(store *identity.Store, trust *identity.TrustStore, fileBytes, bundlePassword, identityPassword []byte, wantFP identity.Fingerprint) (*ImportSummary, error) {
	if store == nil {
		return nil, errors.New("import recovery: store is nil")
	}
	if trust == nil {
		return nil, errors.New("import recovery: trust store is nil")
	}
	inner, err := crypto.Unlock(bundlePassword, fileBytes)
	if err != nil {
		return nil, fmt.Errorf("open recovery bundle: %w", err)
	}
	defer clear(inner)
	var wire bundle
	if err := json.Unmarshal(inner, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode recovery bundle: %w", err)
	}
	if wire.Version != BundleVersion {
		return nil, fmt.Errorf("decode recovery bundle: unsupported version %d: want %d", wire.Version, BundleVersion)
	}
	if wire.ExportedAt.IsZero() {
		return nil, errors.New("decode recovery bundle: exported_at is missing")
	}
	owner, err := identity.ParseFingerprint(wire.Identity)
	if err != nil {
		return nil, fmt.Errorf("decode recovery bundle: %w", err)
	}
	if !owner.Equal(wantFP) {
		return nil, fmt.Errorf("%w: bundle names %s, want %s", pverrors.ErrIntegrity, owner.Grouped(), wantFP.Grouped())
	}
	id, err := identity.ParsePublic(wire.Public)
	if err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
	if !id.Fingerprint.Equal(owner) {
		return nil, fmt.Errorf("%w: bundle identity mismatch", pverrors.ErrIntegrity)
	}
	var identities []*identity.Identity
	restored := make(map[string][]byte, len(wire.Trusted))
	for _, entry := range wire.Trusted {
		fp, err := parseTrustName(entry.Name)
		if err != nil {
			return nil, err
		}
		entryID, err := identity.ParsePublic(entry.Data)
		if err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
		if !entryID.Fingerprint.Equal(fp) {
			return nil, fmt.Errorf("%w: bundle trust entry mismatch", pverrors.ErrIntegrity)
		}
		identities = append(identities, entryID)
		restored[entryID.Fingerprint.String()] = entryID.SignPublic
	}
	listed, err := trust.List()
	if err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
	for _, id := range listed {
		restored[id.Fingerprint.String()] = id.SignPublic
	}
	for _, entry := range wire.Revoked {
		fp, err := parseRevokedName(entry.Name)
		if err != nil {
			return nil, err
		}
		rev, err := identity.DecodeRevocation(entry.Data)
		if err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
		if !rev.Fingerprint.Equal(fp) {
			return nil, fmt.Errorf("%w: bundle revocation entry mismatch", pverrors.ErrIntegrity)
		}
		signerPub, ok := restored[rev.Signer.String()]
		if !ok {
			return nil, fmt.Errorf("%w: bundle revocation signed by unknown %s", pverrors.ErrUntrustedSigner, rev.Signer.Grouped())
		}
		if _, err := identity.VerifyRevocation(entry.Data, signerPub); err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
	}
	if _, err := store.Import(wire.Public); err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
	if _, err := store.ImportPrivate(owner, wire.PrivateSealed, identityPassword); err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
	// No grants until every record is valid and both passwords were proven.
	// Install revocations first so partial writes remain fail-closed.
	for _, entry := range wire.Revoked {
		fp, err := parseRevokedName(entry.Name)
		if err != nil {
			return nil, err
		}
		if err := trust.AddRevocation(fp, entry.Data); err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
	}
	for _, entryID := range identities {
		if err := trust.Add(entryID); err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
	}
	return &ImportSummary{
		Owner:      owner,
		Trusted:    len(wire.Trusted),
		Revoked:    len(wire.Revoked),
		ExportedAt: wire.ExportedAt,
	}, nil
}

// parseTrustName validates a trusted entry name back to its fingerprint.
func parseTrustName(name string) (identity.Fingerprint, error) {
	raw, ok := strings.CutSuffix(name, ".json")
	if !ok || !filepath.IsLocal(name) || strings.Contains(raw, "/") {
		return identity.Fingerprint{}, fmt.Errorf("%w: bad bundle trust name %q", pverrors.ErrIntegrity, name)
	}
	fp, err := identity.ParseFingerprint(raw)
	if err != nil {
		return identity.Fingerprint{}, fmt.Errorf("bundle trust name %q: %w", name, err)
	}
	return fp, nil
}

// parseRevokedName validates a revoked entry name back to its fingerprint.
func parseRevokedName(name string) (identity.Fingerprint, error) {
	raw, ok := strings.CutSuffix(name, ".rev")
	if !ok || !filepath.IsLocal(name) || strings.Contains(raw, "/") {
		return identity.Fingerprint{}, fmt.Errorf("%w: bad bundle revocation name %q", pverrors.ErrIntegrity, name)
	}
	fp, err := identity.ParseFingerprint(raw)
	if err != nil {
		return identity.Fingerprint{}, fmt.Errorf("bundle revocation name %q: %w", name, err)
	}
	return fp, nil
}
