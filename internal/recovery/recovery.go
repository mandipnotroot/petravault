// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package recovery builds single-file client recovery bundles (DESIGN.md
// §5.2): one password-encrypted file holding an identity (public file plus
// the still-sealed private file), the trust view, and head records. The
// bundle never holds decrypted key material — export copies sealed bytes —
// and import proves both passwords by unlocking: the bundle envelope, then
// the restored private key. Bundle import is the explicit operator action
// that may reset head records (DESIGN.md §9).
package recovery

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/verify"
)

// BundleVersion is the recovery bundle format version.
const BundleVersion = 1

// fileEntry carries one client file by its base name with raw bytes. Trust
// names are fingerprints with a fixed suffix; heads names are repository ids
// with .json. Names are validated on import and never trusted as paths.
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
	Heads         []fileEntry `json:"heads"`
}

// ExportSummary reports what one export captured.
type ExportSummary struct {
	Owner      identity.Fingerprint
	Trusted    int
	Revoked    int
	Heads      int
	ExportedAt time.Time
}

// ImportSummary reports what one import restored.
type ImportSummary struct {
	Owner      identity.Fingerprint
	Trusted    int
	Revoked    int
	Heads      int
	ExportedAt time.Time
}

// HeadStatus compares one repository's live and bundled tips.
type HeadStatus struct {
	// Repository is the heads file base name (<repository_id>.json).
	Repository string
	// Live and Bundled hold tip maps fingerprint->snapshot, either possibly nil.
	Live    map[string]string
	Bundled map[string]string
	// State is current, diverged, missing-live, or missing-bundle.
	State string
}

// Export captures fp's recovery bundle and seals it under bundlePassword.
// The private file is copied sealed; export never unlocks keys.
func Export(store *identity.Store, trust *identity.TrustStore, headsDir string, fp identity.Fingerprint, bundlePassword []byte, now func() time.Time) ([]byte, *ExportSummary, error) {
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
		revoked, err := trust.IsRevoked(entry.Fingerprint)
		if err != nil {
			return nil, nil, err
		}
		if !revoked {
			continue
		}
		env, err := trust.RevocationEnvelope(entry.Fingerprint)
		if err != nil {
			return nil, nil, err
		}
		out.Revoked = append(out.Revoked, fileEntry{Name: entry.Fingerprint.String() + ".rev", Data: env})
	}
	heads, err := readHeadsDir(headsDir)
	if err != nil {
		return nil, nil, err
	}
	out.Heads = heads
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
		Heads:      len(out.Heads),
		ExportedAt: out.ExportedAt,
	}, nil
}

// Import opens a bundle under bundlePassword and restores it into store,
// trust, and headsDir, then proves identityPassword unlocks the restored
// private key. The bundle must name wantFP. Heads files are replaced whole:
// import is the explicit operator reset (DESIGN.md §9).
func Import(store *identity.Store, trust *identity.TrustStore, headsDir string, fileBytes, bundlePassword, identityPassword []byte, wantFP identity.Fingerprint) (*ImportSummary, error) {
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
	if _, err := store.Import(wire.Public); err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
	if _, err := store.ImportPrivate(owner, wire.PrivateSealed, identityPassword); err != nil {
		return nil, fmt.Errorf("import recovery: %w", err)
	}
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
		if err := trust.Add(entryID); err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
	}
	restored := make(map[string][]byte, len(wire.Trusted))
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
		if err := trust.AddRevocation(fp, entry.Data); err != nil {
			return nil, fmt.Errorf("import recovery: %w", err)
		}
	}
	for _, entry := range wire.Heads {
		if err := checkHeadsName(entry.Name); err != nil {
			return nil, err
		}
		if err := writeHeadsFile(headsDir, entry.Name, entry.Data); err != nil {
			return nil, err
		}
	}
	return &ImportSummary{
		Owner:      owner,
		Trusted:    len(wire.Trusted),
		Revoked:    len(wire.Revoked),
		Heads:      len(wire.Heads),
		ExportedAt: wire.ExportedAt,
	}, nil
}

// Status opens a bundle and compares its head records with the live ones.
func Status(headsDir string, fileBytes, bundlePassword []byte) ([]HeadStatus, time.Time, error) {
	inner, err := crypto.Unlock(bundlePassword, fileBytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("open recovery bundle: %w", err)
	}
	defer clear(inner)
	var wire bundle
	if err := json.Unmarshal(inner, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, time.Time{}, fmt.Errorf("decode recovery bundle: %w", err)
	}
	if wire.Version != BundleVersion {
		return nil, time.Time{}, fmt.Errorf("decode recovery bundle: unsupported version %d: want %d", wire.Version, BundleVersion)
	}
	var out []HeadStatus
	for _, entry := range wire.Heads {
		if err := checkHeadsName(entry.Name); err != nil {
			return nil, time.Time{}, err
		}
		bundled, err := parseHeadsBytes(entry.Data)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("bundle heads %s: %w", entry.Name, err)
		}
		liveRaw, err := os.ReadFile(filepath.Join(headsDir, entry.Name))
		var live map[string]string
		if err == nil {
			live, err = parseHeadsBytes(liveRaw)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("live heads %s: %w", entry.Name, err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, time.Time{}, fmt.Errorf("read live heads %s: %w", entry.Name, err)
		}
		state := "diverged"
		switch {
		case live == nil:
			state = "missing-live"
		case equalTips(live, bundled):
			state = "current"
		}
		out = append(out, HeadStatus{Repository: entry.Name, Live: live, Bundled: bundled, State: state})
	}
	return out, wire.ExportedAt, nil
}

// readHeadsDir collects validated head-record files. A missing directory
// means no state yet, not an error.
func readHeadsDir(dir string) ([]fileEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list heads: %w", err)
	}
	var out []fileEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || !filepath.IsLocal(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read heads %s: %w", e.Name(), err)
		}
		if _, err := verify.LoadHeads(filepath.Join(dir, e.Name())); err != nil {
			return nil, fmt.Errorf("decode heads %s: %w", e.Name(), err)
		}
		out = append(out, fileEntry{Name: e.Name(), Data: raw})
	}
	return out, nil
}

// writeHeadsFile validates entry bytes through a temp file before
// installing them, so corrupt bundle data never lands in live state.
func writeHeadsFile(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create heads dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "recovery-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp heads: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp heads: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp heads: %w", err)
	}
	if _, err := verify.LoadHeads(tmpName); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("decode bundle heads %s: %w", name, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp heads: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("install heads %s: %w", name, err)
	}
	return nil
}

// parseHeadsBytes validates heads JSON through a temp file and returns
// source->snapshot tips.
func parseHeadsBytes(data []byte) (map[string]string, error) {
	f, err := os.CreateTemp("", "recovery-heads-*.json")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	defer os.Remove(name)
	heads, err := verify.LoadHeads(name)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(heads))
	for source, h := range heads {
		out[source] = h.Snapshot
	}
	return out, nil
}

func equalTips(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
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

// checkHeadsName validates a heads file name.
func checkHeadsName(name string) error {
	if !strings.HasSuffix(name, ".json") || !filepath.IsLocal(name) || strings.Contains(name, "/") {
		return fmt.Errorf("%w: bad bundle heads name %q", pverrors.ErrIntegrity, name)
	}
	return nil
}
