// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package identity

import (
	"bytes"
	"cmp"
	"crypto/hpke"
	"crypto/mldsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	json "encoding/json/v2"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Keystore file names inside one identity directory
// ($XDG_DATA_HOME/petravault/identities/<fingerprint>/). Private keys live
// only here, never in the repository (DESIGN.md §4.4).
const (
	publicFileName  = "public.json"
	privateFileName = "private.sealed"
)

// privateFile is the plaintext sealed by the password (Password → Argon2id →
// KEK → XChaCha20-Poly1305, DESIGN.md §4.4). It carries seeds, never derived
// keys, and no password verifier beyond the sealed blob itself.
type privateFile struct {
	Version    int    `json:"version"`
	SignSeed   string `json:"sign_seed"`
	KEMPrivate string `json:"kem_private"`
}

// Store is a client-side keystore: one directory per identity holding
// public.json and, for owned identities, a password-sealed private.sealed.
// Imported identities hold public.json only until trusted. The zero value is
// invalid; use NewStore.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir.
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// ListedIdentity pairs an Identity with whether its private key is present.
type ListedIdentity struct {
	Identity Identity
	Owned    bool
}

// Create generates a fresh identity (ML-DSA-65 signing + X-Wing KEM,
// DESIGN.md §5), seals its private keys under password, and stores both
// halves. now supplies the creation time; nil means time.Now.
func (s *Store) Create(name string, password []byte, now func() time.Time) (*Identity, error) {
	name = cmp.Or(name, "")
	if name == "" || len(name) > MaxNameLength || !utf8.ValidString(name) {
		return nil, fmt.Errorf("%w: invalid identity name: want 1..%d UTF-8 chars", pverrors.ErrUsage, MaxNameLength)
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if now == nil {
		now = time.Now
	}
	signPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	kemPriv, err := GenerateKEM()
	if err != nil {
		return nil, fmt.Errorf("generate KEM key: %w", err)
	}
	signPub := signPriv.PublicKey().Bytes()
	kemPub := kemPriv.PublicKey().Bytes()
	fp, err := ComputeFingerprint(signPub, kemPub)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		Fingerprint: fp,
		Name:        name,
		CreatedAt:   now().UTC(),
		SignPublic:  signPub,
		KEMPublic:   kemPub,
	}
	if id.CreatedAt.IsZero() {
		return nil, errors.New("create identity: creation time is missing")
	}

	dir := filepath.Join(s.dir, fp.String())
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("create identity: %s already exists", fp.Grouped())
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat identity dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}

	publicJSON, err := MarshalPublic(id)
	if err != nil {
		return nil, err
	}
	if err := writeDurableFile(filepath.Join(dir, publicFileName), publicJSON, 0o644); err != nil {
		return nil, err
	}

	kemPrivBytes, err := kemPriv.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode KEM private key: %w", err)
	}
	inner, err := json.Marshal(privateFile{
		Version:    Version,
		SignSeed:   base64.StdEncoding.EncodeToString(signPriv.Bytes()),
		KEMPrivate: base64.StdEncoding.EncodeToString(kemPrivBytes),
	})
	clear(kemPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("marshal private identity: %w", err)
	}
	sealed, err := crypto.Lock(password, inner)
	clear(inner)
	if err != nil {
		return nil, err
	}
	if err := writeDurableFile(filepath.Join(dir, privateFileName), sealed, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

// List returns every identity in the store, sorted by fingerprint. A corrupt
// entry fails the whole list (fail closed).
func (s *Store) List() ([]ListedIdentity, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list identities: %w", err)
	}
	var out []ListedIdentity
	for _, e := range entries {
		if !e.IsDir() {
			return nil, fmt.Errorf("list identities: unexpected file %q", e.Name())
		}
		fp, err := ParseFingerprint(e.Name())
		if err != nil {
			return nil, fmt.Errorf("list identities: %w", err)
		}
		id, err := s.LoadPublic(fp)
		if err != nil {
			return nil, err
		}
		_, statErr := os.Stat(filepath.Join(s.dir, e.Name(), privateFileName))
		owned := statErr == nil
		if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat private key: %w", statErr)
		}
		out = append(out, ListedIdentity{Identity: *id, Owned: owned})
	}
	slices.SortFunc(out, func(a, b ListedIdentity) int {
		return cmp.Compare(a.Identity.Fingerprint.String(), b.Identity.Fingerprint.String())
	})
	return out, nil
}

// LoadPublic loads the public half of fp. A fingerprint mismatch or corrupt
// file wraps ErrIntegrity.
func (s *Store) LoadPublic(fp Fingerprint) (*Identity, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, fp.String(), publicFileName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: unknown identity %s", pverrors.ErrUsage, fp.Grouped())
		}
		return nil, fmt.Errorf("read identity: %w", err)
	}
	id, err := ParsePublic(data)
	if err != nil {
		return nil, err
	}
	if !id.Fingerprint.Equal(fp) {
		return nil, fmt.Errorf("identity %s: %w: fingerprint mismatch", fp.Grouped(), pverrors.ErrIntegrity)
	}
	return id, nil
}

// LoadPrivate unlocks fp with password and returns its private keys. A wrong
// password or tampered store fails authentication with no partial output. A
// private file readable by group or others is refused. The derived publics
// must match the stored publics, or the store is corrupt.
func (s *Store) LoadPrivate(fp Fingerprint, password []byte) (*PrivateIdentity, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	sealedPath := filepath.Join(s.dir, fp.String(), privateFileName)
	fi, err := os.Stat(sealedPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: identity %s has no private key here", pverrors.ErrUsage, fp.Grouped())
		}
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s: permissions %v too open, want 0600", fp.Grouped(), fi.Mode().Perm())
	}
	sealed, err := os.ReadFile(sealedPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	inner, err := crypto.Unlock(password, sealed)
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	var wire privateFile
	if err := json.Unmarshal(inner, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("decode private key: unsupported version %d: want %d", wire.Version, Version)
	}
	seed, err := base64.StdEncoding.DecodeString(wire.SignSeed)
	if err != nil || len(seed) != SignSeedSize {
		return nil, errors.New("decode private key: invalid signing seed")
	}
	defer clear(seed)
	kemRaw, err := base64.StdEncoding.DecodeString(wire.KEMPrivate)
	if err != nil || len(kemRaw) != KEMPrivateSize {
		return nil, errors.New("decode private key: invalid KEM private key")
	}
	defer clear(kemRaw)
	signPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, fmt.Errorf("decode private key: invalid signing seed: %w", err)
	}
	kemPriv, err := hpke.MLKEM768X25519().NewPrivateKey(kemRaw)
	if err != nil {
		return nil, fmt.Errorf("decode private key: invalid KEM private key: %w", err)
	}
	pub, err := s.LoadPublic(fp)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signPriv.PublicKey().Bytes(), pub.SignPublic) {
		return nil, fmt.Errorf("private key %s: %w: public mismatch", fp.Grouped(), pverrors.ErrIntegrity)
	}
	derivedKemPub := kemPriv.PublicKey().Bytes()
	if !bytes.Equal(derivedKemPub, pub.KEMPublic) {
		return nil, fmt.Errorf("private key %s: %w: public mismatch", fp.Grouped(), pverrors.ErrIntegrity)
	}
	return &PrivateIdentity{Public: *pub, signPriv: signPriv, kemPriv: kemPriv}, nil
}

// ImportPrivate stores a password-sealed private file for fp, then proves
// it opens with password and matches the stored public half. It returns the
// unlocked identity, so bundle import confirms the password works. A
// mismatch removes the written file and fails closed.
func (s *Store) ImportPrivate(fp Fingerprint, sealed, password []byte) (*PrivateIdentity, error) {
	if len(sealed) == 0 {
		return nil, errors.New("import private key: empty sealed file")
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	dir := filepath.Join(s.dir, fp.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}
	path := filepath.Join(dir, privateFileName)
	if err := writeDurableFile(path, sealed, 0o600); err != nil {
		return nil, err
	}
	priv, err := s.LoadPrivate(fp, password)
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("import private key: %w", err)
	}
	return priv, nil
}

// SealedPrivate returns the raw password-sealed private file for fp, for
// recovery-bundle export. The bytes stay sealed; export never sees keys.
func (s *Store) SealedPrivate(fp Fingerprint) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, fp.String(), privateFileName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: identity %s has no private key here", pverrors.ErrUsage, fp.Grouped())
		}
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return data, nil
}

// Export writes fp's public file to w.
func (s *Store) Export(fp Fingerprint, w io.Writer) error {
	id, err := s.LoadPublic(fp)
	if err != nil {
		return err
	}
	data, err := MarshalPublic(id)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("export identity %s: %w", fp.Grouped(), err)
	}
	return nil
}

// Import stores a public file exported by Export. The fingerprint is
// recomputed and must match; a mismatch wraps ErrIntegrity. An existing
// private half is preserved.
func (s *Store) Import(data []byte) (*Identity, error) {
	id, err := ParsePublic(data)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(s.dir, id.Fingerprint.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity dir: %w", err)
	}
	publicJSON, err := MarshalPublic(id)
	if err != nil {
		return nil, err
	}
	if err := writeDurableFile(filepath.Join(dir, publicFileName), publicJSON, 0o644); err != nil {
		return nil, err
	}
	return id, nil
}

// Find resolves query as a fingerprint in any accepted form, or as an exact
// identity name. An ambiguous name or unknown value wraps ErrUsage.
func (s *Store) Find(query string) (*Identity, error) {
	if fp, err := ParseFingerprint(query); err == nil {
		return s.LoadPublic(fp)
	}
	listed, err := s.List()
	if err != nil {
		return nil, err
	}
	var matched []Identity
	for _, e := range listed {
		if e.Identity.Name == query {
			matched = append(matched, e.Identity)
		}
	}
	switch len(matched) {
	case 0:
		return nil, fmt.Errorf("%w: unknown identity %q", pverrors.ErrUsage, query)
	case 1:
		id := matched[0]
		return &id, nil
	default:
		return nil, fmt.Errorf("%w: ambiguous identity %q: matches %d identities, use a fingerprint", pverrors.ErrUsage, query, len(matched))
	}
}

// writeDurableFile writes data to path via a temp file in the same
// directory, Sync, Close, Rename, then Sync the directory, so a crash never
// leaves a half-written key file.
func writeDurableFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	writeErr := func() error {
		if _, err := tmp.Write(data); err != nil {
			return fmt.Errorf("write temp: %w", err)
		}
		if err := tmp.Chmod(perm); err != nil {
			return fmt.Errorf("chmod temp: %w", err)
		}
		if err := tmp.Sync(); err != nil {
			return fmt.Errorf("sync temp: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close temp: %w", err)
		}
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("rename: %w", err)
		}
		return syncDir(dir)
	}()
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
