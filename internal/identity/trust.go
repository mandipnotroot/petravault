// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	pverrors "petravault/internal/errors"
)

// Trust subdirectories under the trust root
// ($XDG_CONFIG_HOME/petravault/trust/). The authoritative trust list is
// client-local: copies of public keys in the repository are advisory only,
// and a snapshot is accepted only if its signer is trusted here and not
// revoked (DESIGN.md §5.2).
const (
	trustedDirName = "trusted-keys"
	revokedDirName = "revoked"
)

// TrustStore is the client-local trust list. Trusted public keys live in
// trusted-keys/<fingerprint>.json and verified revocations in
// revoked/<fingerprint>.rev. Revocation records only add: nothing here ever
// removes a revocation.
type TrustStore struct {
	dir string
}

// NewTrustStore returns a TrustStore rooted at dir.
func NewTrustStore(dir string) *TrustStore {
	return &TrustStore{dir: dir}
}

func (t *TrustStore) trustedPath(fp Fingerprint) string {
	return filepath.Join(t.dir, trustedDirName, fp.String()+".json")
}

func (t *TrustStore) revokedPath(fp Fingerprint) string {
	return filepath.Join(t.dir, revokedDirName, fp.String()+".rev")
}

// Add trusts id. The fingerprint is recomputed from the public keys and must
// match: a repository-side copy that does not hash to the confirmed
// fingerprint is rejected (DESIGN.md §5.1). The full fingerprint is the
// caller's responsibility to have confirmed out of band.
func (t *TrustStore) Add(id *Identity) error {
	if id == nil {
		return errors.New("trust add: identity is nil")
	}
	want, err := ComputeFingerprint(id.SignPublic, id.KEMPublic)
	if err != nil {
		return err
	}
	if !want.Equal(id.Fingerprint) {
		return fmt.Errorf("trust add %s: %w: fingerprint mismatch", id.Fingerprint.Grouped(), pverrors.ErrIntegrity)
	}
	data, err := MarshalPublic(id)
	if err != nil {
		return err
	}
	if err := writeDurableFile(t.trustedPath(id.Fingerprint), data, 0o644); err != nil {
		return fmt.Errorf("trust add %s: %w", id.Fingerprint.Grouped(), err)
	}
	return nil
}

// Remove untrusts fp. Revocations are never removed: a revoked key stays
// revoked.
func (t *TrustStore) Remove(fp Fingerprint) error {
	if err := os.Remove(t.trustedPath(fp)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: identity %s is not trusted", pverrors.ErrUsage, fp.Grouped())
		}
		return fmt.Errorf("trust remove %s: %w", fp.Grouped(), err)
	}
	return nil
}

// List returns every trusted identity, including revoked ones (callers check
// IsRevoked to mark them), sorted by fingerprint. A corrupt entry fails the
// whole list.
func (t *TrustStore) List() ([]Identity, error) {
	entries, err := os.ReadDir(filepath.Join(t.dir, trustedDirName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list trusted keys: %w", err)
	}
	var out []Identity
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("list trusted keys: unexpected directory %q", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(t.dir, trustedDirName, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("list trusted keys: %w", err)
		}
		id, err := ParsePublic(data)
		if err != nil {
			return nil, err
		}
		// Bind the filename to the recomputed fingerprint, like the
		// keystore loader: a misnamed-but-valid file must not list under
		// a name that IsTrusted would resolve differently.
		if e.Name() != id.Fingerprint.String()+".json" {
			return nil, fmt.Errorf("%w: trusted key file %q does not match its fingerprint", pverrors.ErrIntegrity, e.Name())
		}
		out = append(out, *id)
	}
	slices.SortFunc(out, func(a, b Identity) int {
		return cmp.Compare(a.Fingerprint.String(), b.Fingerprint.String())
	})
	return out, nil
}

// IsTrusted reports whether fp is trusted and not revoked. Existence is the
// decision: trust entries are verified at Add time, and callers verify
// revocation signatures before AddRevocation time.
func (t *TrustStore) IsTrusted(fp Fingerprint) (bool, error) {
	if revoked, err := t.IsRevoked(fp); err != nil {
		return false, err
	} else if revoked {
		return false, nil
	}
	_, err := os.Stat(t.trustedPath(fp))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat trusted key: %w", err)
	}
	return true, nil
}

// IsRevoked reports whether a revocation record exists for fp.
func (t *TrustStore) IsRevoked(fp Fingerprint) (bool, error) {
	_, err := os.Stat(t.revokedPath(fp))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat revocation: %w", err)
	}
	return true, nil
}

// TrustedPublic returns the trusted public keys for fp, or an untrusted
// error wrapping ErrUntrustedSigner when fp is unknown or revoked.
func (t *TrustStore) TrustedPublic(fp Fingerprint) (*Identity, error) {
	trusted, err := t.IsTrusted(fp)
	if err != nil {
		return nil, err
	}
	if !trusted {
		return nil, fmt.Errorf("%w: %s", pverrors.ErrUntrustedSigner, fp.Grouped())
	}
	data, err := os.ReadFile(t.trustedPath(fp))
	if err != nil {
		return nil, fmt.Errorf("read trusted key: %w", err)
	}
	return ParsePublic(data)
}

// AddRevocation stores a revocation envelope for target. The caller must
// have verified the envelope signature against its own trust list before
// storing: this method checks only that the payload names target, not who
// signed it. Storing is idempotent: any one valid revocation disqualifies
// the key.
func (t *TrustStore) AddRevocation(target Fingerprint, envBytes []byte) error {
	rev, err := decodeRevocationEnvelope(envBytes)
	if err != nil {
		return err
	}
	if !rev.Fingerprint.Equal(target) {
		return fmt.Errorf("revocation names %s, want %s", rev.Fingerprint.Grouped(), target.Grouped())
	}
	if err := writeDurableFile(t.revokedPath(target), envBytes, 0o644); err != nil {
		return fmt.Errorf("store revocation %s: %w", target.Grouped(), err)
	}
	return nil
}

// RevocationEnvelope returns the stored revocation envelope for a revoked fp.
// PublishTrustList embeds it so recovery preserves disqualifications.
func (t *TrustStore) RevocationEnvelope(fp Fingerprint) ([]byte, error) {
	data, err := os.ReadFile(t.revokedPath(fp))
	if err != nil {
		return nil, fmt.Errorf("read revocation %s: %w", fp.Grouped(), err)
	}
	return data, nil
}

// RevocationEnvelopes returns every retained tombstone, including those whose
// targets have been removed from active trust. Filename order is deterministic.
func (t *TrustStore) RevocationEnvelopes() ([][]byte, error) {
	entries, err := os.ReadDir(filepath.Join(t.dir, revokedDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list revocations: %w", err)
	}
	var out [][]byte
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("%w: unexpected revocation entry %q", pverrors.ErrIntegrity, entry.Name())
		}
		raw, err := os.ReadFile(filepath.Join(t.dir, revokedDirName, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read revocation: %w", err)
		}
		rev, err := decodeRevocationEnvelope(raw)
		if err != nil {
			return nil, err
		}
		if entry.Name() != rev.Fingerprint.String()+".rev" {
			return nil, fmt.Errorf("%w: revocation filename does not match its target", pverrors.ErrIntegrity)
		}
		out = append(out, raw)
	}
	return out, nil
}
