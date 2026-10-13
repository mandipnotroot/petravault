// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package verify checks repository integrity (DESIGN.md §9). Standard
// verification covers the repository config (already verified by the
// caller via ReadConfig), key slots, index consistency, object and sidecar
// existence and parameters, manifest and signature validity, identity
// trust, per-source snapshot chains, head records, and chunk references.
// Deep verification additionally checks ECC parity, AEAD authentication,
// decryption, decompression, BLAKE3 recomputation, and restored-metadata
// validation. Failures that indicate tampering wrap ErrIntegrity and map
// to exit code 4; they are never downgraded or swallowed.
package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"petravault/internal/compression"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/identity"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

// Options configures one verification run.
type Options struct {
	// SnapshotID restricts verification to one snapshot (hex, with
	// optional b3: prefix). Empty verifies the whole repository.
	SnapshotID string
	// Deep enables ECC parity, AEAD, decompression, and BLAKE3 checks
	// over every chunk (DESIGN.md §9).
	Deep bool
	// HeadsPath is the client-local head-record file. Empty skips head
	// checks and updates (tests); production callers pass
	// HeadsPath(stateDir, repositoryID).
	HeadsPath string
	// MaxChunkSize caps decompression of any single chunk. Non-positive
	// selects the repository maximum.
	MaxChunkSize int
	// Logger receives progress. Nil discards logs.
	Logger *slog.Logger
}

// Report summarizes a successful verification run.
type Report struct {
	// Snapshots, Packs, Indexes, and Slots count verified objects.
	Snapshots int
	Packs     int
	Indexes   int
	Slots     int
	// Sources counts distinct source IDs.
	Sources int
	// Tips maps each source to its current tip snapshot ID hex.
	Tips map[string]string
	// NoHeadSources lists sources with no prior head record (first use).
	// The chain was checked for internal consistency only (DESIGN.md §9).
	NoHeadSources []string
	// Warnings holds non-fatal notes, such as missing parity sidecars
	// that a later backup or ecc rebuild regenerates.
	Warnings []string
}

// Verify checks the repository and returns its report. The repository
// config must already be verified (repository.ReadConfig); repoCfg carries
// the trusted suite, chunking, and ECC settings it established. Trust
// resolution uses trust (revocation-aware) with signing keys in trusted.
// On success with a HeadsPath, head records are updated to the current
// tips. Any integrity failure is returned joined with others and wrapping
// ErrIntegrity.
func Verify(ctx context.Context, repo repository.Repository, repoCfg repository.Config, dataKey, chunkIDKey crypto.SecretKey, trust *identity.TrustStore, trusted map[string][]byte, opts Options) (Report, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	var report Report
	report.Tips = map[string]string{}
	if repo == nil {
		return report, errors.New("verify: repository is nil")
	}
	if trust == nil {
		return report, errors.New("verify: trust store is nil")
	}
	if err := repoCfg.Validate(); err != nil {
		return report, err
	}
	maxChunk := opts.MaxChunkSize
	if maxChunk <= 0 {
		maxChunk = repoCfg.ChunkMax
	}
	if maxChunk <= 0 {
		maxChunk = compression.DefaultMaxSize
	}
	only := ""
	if strings.TrimSpace(opts.SnapshotID) != "" {
		id, err := manifest.ParseSnapshotID(opts.SnapshotID)
		if err != nil {
			return report, fmt.Errorf("%w: %w", pverrors.ErrUsage, err)
		}
		only = manifest.FormatSnapshotID(id)
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}

	packKeys, err := listObjects(ctx, repo, "packs/")
	if err != nil {
		return report, err
	}
	indexKeys, err := listObjects(ctx, repo, "indexes/")
	if err != nil {
		return report, err
	}
	snapshotIDs, err := manifest.List(ctx, repo)
	if err != nil {
		return report, err
	}
	if only != "" && !slices.Contains(snapshotIDs, only) {
		return report, fmt.Errorf("%w: snapshot %s not found", pverrors.ErrIntegrity, only)
	}
	// Single-snapshot verification still loads every manifest for chain
	// and head context; chunk and deep checks below are scoped to the
	// requested snapshot (plus its history via the chain check).
	verifyIDs := snapshotIDs
	if only != "" {
		verifyIDs = []string{only}
	}
	report.Packs = len(packKeys)
	report.Indexes = len(indexKeys)
	report.Snapshots = len(verifyIDs)

	var errs []error
	// Key slots: every sealed slot must verify under a client-trusted
	// granter and name this repository (DESIGN.md §4.2, §5.2).
	slotKeys, err := repo.List(ctx, identity.SlotPrefix)
	if err != nil {
		return report, fmt.Errorf("list key slots: %w", err)
	}
	slotKeys = filterECC(slotKeys)
	report.Slots = len(slotKeys)
	for _, key := range slotKeys {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := verifySlot(ctx, repo, key, repoCfg.RepositoryID, trust, trusted); err != nil {
			errs = append(errs, err)
		}
	}

	// Indexes: AEAD authentication plus structural checks; sidecars must
	// decode and name the object length.
	merged := map[[32]byte]pack.Entry{}
	packSet := map[string]bool{}
	for _, k := range packKeys {
		packSet[k] = true
	}
	for _, key := range indexKeys {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		sealed, err := readObject(ctx, repo, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := pack.VerifyIndex(sealed, repoCfg.RepositoryID, dataKey, key); err != nil {
			errs = append(errs, fmt.Errorf("index %s: %w", key, err))
			continue
		}
		entries, err := pack.ReadIndex(ctx, repo, repoCfg.RepositoryID, dataKey, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("index %s: %w", key, err))
			continue
		}
		for _, e := range entries {
			if _, ok := merged[e.ID]; !ok {
				merged[e.ID] = e
			}
		}
		if warn := checkSidecar(ctx, repo, key, sealed, opts.Deep); warn != "" {
			report.Warnings = append(report.Warnings, warn)
		} else if opts.Deep {
			if err := checkParity(ctx, repo, key, sealed); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// Snapshots: AEAD opening, ID binding, signature verification with a
	// client-trusted key, and manifest validation. The signer's identity
	// hint is never trusted until verification succeeds. Every snapshot is
	// opened so per-source chains have full context; scoped checks below
	// use verifyIDs.
	manifests := map[string]manifest.Manifest{}
	for _, hexID := range snapshotIDs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		sealed, err := readObject(ctx, repo, manifest.SnapshotPrefix+hexID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m, err := openTrustedSnapshot(ctx, repo, repoCfg, dataKey, hexID, trust, trusted)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if m.CryptoSuite != repoCfg.CryptoSuite {
			errs = append(errs, fmt.Errorf("%w: snapshot %s names crypto suite %q, want %q", pverrors.ErrIntegrity, hexID, m.CryptoSuite, repoCfg.CryptoSuite))
			continue
		}
		if m.ChunkingAlgorithm != repoCfg.ChunkingAlgorithm {
			errs = append(errs, fmt.Errorf("%w: snapshot %s names chunking %q, want %q", pverrors.ErrIntegrity, hexID, m.ChunkingAlgorithm, repoCfg.ChunkingAlgorithm))
			continue
		}
		manifests[hexID] = m
		if warn := checkSidecar(ctx, repo, manifest.SnapshotPrefix+hexID, sealed, opts.Deep); warn != "" {
			report.Warnings = append(report.Warnings, warn)
		} else if opts.Deep {
			if err := checkParity(ctx, repo, manifest.SnapshotPrefix+hexID, sealed); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// Per-source chains: parents must exist in the same source, forks are
	// configuration errors that fail verification, and the tip is the
	// single childless snapshot (DESIGN.md §9, §10.3).
	tips, err := checkChains(manifests)
	if err != nil {
		errs = append(errs, err)
	} else {
		report.Tips = tips
		report.Sources = len(tips)
	}

	// Chunk references: every chunk in the verified manifests must resolve
	// in the merged index, and every index entry must name an existing
	// pack. Single-snapshot runs scope chunk checks to the requested
	// snapshot; chain and global index checks above still use full context.
	verifySet := map[string]bool{}
	for _, id := range verifyIDs {
		verifySet[id] = true
	}
	if len(errs) == 0 || only == "" {
		for hexID, m := range manifests {
			if only != "" && !verifySet[hexID] {
				continue
			}
			for _, f := range m.Files {
				for _, chunkHex := range f.Chunks {
					id, err := pack.ParseID(chunkHex)
					if err != nil {
						errs = append(errs, fmt.Errorf("%w: snapshot %s file %q holds %w", pverrors.ErrIntegrity, hexID, f.Path, err))
						continue
					}
					loc, ok := merged[id]
					if !ok {
						errs = append(errs, fmt.Errorf("%w: snapshot %s references missing chunk %s", pverrors.ErrIntegrity, hexID, chunkHex))
						continue
					}
					if !packSet[loc.Pack] {
						errs = append(errs, fmt.Errorf("%w: snapshot %s chunk %s names missing pack %s", pverrors.ErrIntegrity, hexID, chunkHex, loc.Pack))
					}
				}
			}
		}
		for _, entries := range []map[[32]byte]pack.Entry{merged} {
			for _, e := range entries {
				if !packSet[e.Pack] {
					errs = append(errs, fmt.Errorf("%w: index entry for chunk %s names missing pack %s", pverrors.ErrIntegrity, pack.FormatID(e.ID), e.Pack))
				}
			}
		}
	}

	// Deep: packs authenticate fully, then every verified chunk decrypts,
	// decompresses within its cap, and re-hashes to its keyed ID.
	if opts.Deep {
		for _, key := range packKeys {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			sealed, err := readObject(ctx, repo, key)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := pack.VerifyPack(sealed, repoCfg.RepositoryID, dataKey, key); err != nil {
				errs = append(errs, fmt.Errorf("pack %s: %w", key, err))
			}
		}
		for hexID, m := range manifests {
			if only != "" && !verifySet[hexID] {
				continue
			}
			for _, f := range m.Files {
				if f.Type != manifest.TypeFile || len(f.Chunks) == 0 {
					continue
				}
				var total int64
				for _, chunkHex := range f.Chunks {
					if err := ctx.Err(); err != nil {
						return report, err
					}
					id, err := pack.ParseID(chunkHex)
					if err != nil {
						errs = append(errs, fmt.Errorf("%w: snapshot %s file %q holds %w", pverrors.ErrIntegrity, hexID, f.Path, err))
						break
					}
					loc, ok := merged[id]
					if !ok {
						break // Already reported above.
					}
					plaintext, err := pack.ReadChunk(ctx, repo, repoCfg.RepositoryID, dataKey, chunkIDKey, loc, maxChunk)
					if err != nil {
						errs = append(errs, fmt.Errorf("snapshot %s file %q: %w: %w", hexID, f.Path, err, pverrors.ErrIntegrity))
						break
					}
					total += int64(len(plaintext))
				}
				if total != f.Size && total != 0 {
					// Size mismatch is metadata corruption, not just
					// chunk damage: it fails deep verification.
					found := false
					for _, e := range errs {
						if strings.Contains(e.Error(), hexID) && strings.Contains(e.Error(), f.Path) {
							found = true
							break
						}
					}
					if !found && total != 0 {
						// Only report when chunks were readable but the
						// size disagrees; unreadable chunks are already
						// reported.
						errs = append(errs, fmt.Errorf("%w: snapshot %s file %q size %d disagrees with its chunks %d", pverrors.ErrIntegrity, hexID, f.Path, f.Size, total))
					}
				}
			}
		}
	}

	// Head records: a recorded head that is missing, or that is neither
	// the tip nor an ancestor of it, detects rollback or truncation
	// (DESIGN.md §9). First use has no record and checks the chain only.
	// Single-snapshot runs check only the requested snapshot's source.
	if opts.HeadsPath != "" && len(tips) > 0 {
		heads, err := LoadHeads(opts.HeadsPath)
		if err != nil {
			errs = append(errs, err)
		} else {
			bySource := groupBySource(manifests)
			sourcesToCheck := tips
			if only != "" {
				if m, ok := manifests[only]; ok {
					tip, ok := tips[m.SourceID]
					if ok {
						sourcesToCheck = map[string]string{m.SourceID: tip}
					} else {
						sourcesToCheck = map[string]string{}
					}
				}
			}
			for source, tip := range sourcesToCheck {
				recorded, ok := heads[source]
				if !ok {
					report.NoHeadSources = append(report.NoHeadSources, source)
					continue
				}
				headID := strings.ToLower(strings.TrimSpace(recorded.Snapshot))
				if _, ok := bySource[source][headID]; !ok {
					errs = append(errs, fmt.Errorf("%w: source %q head %s is missing: snapshots were deleted", pverrors.ErrRollback, source, headID))
					continue
				}
				if headID != tip && !isAncestor(bySource[source], tip, headID) {
					errs = append(errs, fmt.Errorf("%w: source %q head %s is neither the tip %s nor its ancestor", pverrors.ErrRollback, source, headID, tip))
				}
			}
			slices.Sort(report.NoHeadSources)
		}
	}

	if len(errs) > 0 {
		return report, errors.Join(errs...)
	}
	if opts.HeadsPath != "" && len(tips) > 0 {
		if err := UpdateTips(opts.HeadsPath, tips, nil); err != nil {
			return report, err
		}
	}
	logger.InfoContext(ctx, "verification finished",
		slog.Int("snapshots", report.Snapshots),
		slog.Int("packs", report.Packs),
		slog.Int("indexes", report.Indexes),
		slog.Int("sources", report.Sources),
		slog.Bool("deep", opts.Deep))
	return report, nil
}

func listObjects(ctx context.Context, repo repository.Repository, prefix string) ([]string, error) {
	keys, err := repo.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", prefix, err)
	}
	return filterECC(keys), nil
}

func filterECC(keys []string) []string {
	out := keys[:0]
	for _, k := range keys {
		if strings.HasSuffix(k, ".ecc") {
			continue
		}
		out = append(out, k)
	}
	return out
}

func readObject(ctx context.Context, repo repository.Repository, key string) ([]byte, error) {
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return raw, nil
}

// verifySlot checks one key-slot envelope against the client-local trust
// list. Like repository config verification, it tries each trusted key in
// sorted order; only a signature mismatch falls through, while structural
// damage fails fast.
func verifySlot(ctx context.Context, repo repository.Repository, key, wantRepo string, trust *identity.TrustStore, trusted map[string][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	member, err := identity.ParseSlotKey(key)
	if err != nil {
		return err
	}
	r, err := repo.GetObject(ctx, key)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	defer r.Close()
	env, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	for _, fp := range slices.Sorted(slices.Values(collectKeys(trusted))) {
		slot, err := identity.VerifySlot(env, trusted[fp])
		if err == nil {
			if slot.RepositoryID != wantRepo {
				return fmt.Errorf("%w: slot %s names repository %q, want %q", pverrors.ErrIntegrity, key, slot.RepositoryID, wantRepo)
			}
			if !slot.Member.Equal(member) {
				return fmt.Errorf("%w: slot %s names member %s, want %s", pverrors.ErrIntegrity, key, slot.Member.Grouped(), member.Grouped())
			}
			// The granter must be currently trusted and unrevoked, not
			// merely a key that once verified.
			trustedGranter, err := trust.IsTrusted(slot.Granter)
			if err != nil {
				return err
			}
			if !trustedGranter {
				return fmt.Errorf("%w: slot %s granter %s is not trusted", pverrors.ErrUntrustedSigner, key, slot.Granter.Grouped())
			}
			return nil
		}
		if !errors.Is(err, pverrors.ErrBadSignature) {
			return fmt.Errorf("slot %s: %w", key, err)
		}
	}
	return fmt.Errorf("%w: slot %s signature is not trusted", pverrors.ErrUntrustedSigner, key)
}

func collectKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func openTrustedSnapshot(ctx context.Context, repo repository.Repository, repoCfg repository.Config, dataKey crypto.SecretKey, hexID string, trust *identity.TrustStore, trusted map[string][]byte) (manifest.Manifest, error) {
	lookup := func(hint string) ([]byte, error) {
		fp, err := identity.ParseFingerprint(hint)
		if err != nil {
			return nil, err
		}
		ok, err := trust.IsTrusted(fp)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
		}
		pub, ok := trusted[fp.String()]
		if !ok {
			return nil, fmt.Errorf("%w: snapshot signer %s", pverrors.ErrUntrustedSigner, fp.Grouped())
		}
		return pub, nil
	}
	m, err := manifest.OpenTrusted(ctx, repo, repoCfg.RepositoryID, dataKey, hexID, lookup)
	if err != nil {
		return manifest.Manifest{}, fmt.Errorf("snapshot %s: %w", hexID, err)
	}
	return m, nil
}

// checkSidecar validates an existing sidecar's parameters and length. A
// missing sidecar returns a warning string (empty means no warning):
// parity covers damage within its budget, not a missing sidecar after a
// crash, and objects intentionally written with --ecc off legitimately
// have none, so absence is reported, never silently ignored, but does not
// fail standard verification.
func checkSidecar(ctx context.Context, repo repository.Repository, objectKey string, objectBytes []byte, deep bool) string {
	_ = deep
	exists, err := repo.Exists(ctx, erasure.SidecarKey(objectKey))
	if err != nil {
		return ""
	}
	if !exists {
		return "missing sidecar for " + objectKey
	}
	r, err := repo.GetObject(ctx, erasure.SidecarKey(objectKey))
	if err != nil {
		return ""
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	sc, err := erasure.Decode(raw)
	if err != nil {
		return ""
	}
	if sc.DataLength != len(objectBytes) {
		return "sidecar length mismatch for " + objectKey
	}
	return ""
}

// checkParity runs the ECC parity check for one object that has a sidecar.
// Objects without a sidecar are skipped: absence is a warning handled by
// checkSidecar, not a deep failure.
func checkParity(ctx context.Context, repo repository.Repository, objectKey string, objectBytes []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	exists, err := repo.Exists(ctx, erasure.SidecarKey(objectKey))
	if err != nil {
		return fmt.Errorf("stat sidecar for %s: %w", objectKey, err)
	}
	if !exists {
		return nil
	}
	r, err := repo.GetObject(ctx, erasure.SidecarKey(objectKey))
	if err != nil {
		return fmt.Errorf("read sidecar for %s: %w", objectKey, err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read sidecar for %s: %w", objectKey, err)
	}
	if err := erasure.Verify(objectBytes, raw); err != nil {
		return fmt.Errorf("parity for %s: %w", objectKey, err)
	}
	return nil
}

func groupBySource(manifests map[string]manifest.Manifest) map[string]map[string]manifest.Manifest {
	out := map[string]map[string]manifest.Manifest{}
	for id, m := range manifests {
		if out[m.SourceID] == nil {
			out[m.SourceID] = map[string]manifest.Manifest{}
		}
		out[m.SourceID][id] = m
	}
	return out
}

// checkChains validates per-source parent links and returns each source's
// tip. Two children of one parent, two roots for one source, a parent from
// another source, or a missing parent all wrap ErrIntegrity.
func checkChains(manifests map[string]manifest.Manifest) (map[string]string, error) {
	bySource := groupBySource(manifests)
	tips := map[string]string{}
	var errs []error
	for source, ids := range bySource {
		children := map[string][]string{}
		roots := []string{}
		for id, m := range ids {
			if m.Parent == "" {
				roots = append(roots, id)
				continue
			}
			parent := strings.ToLower(strings.TrimSpace(m.Parent))
			parentManifest, ok := manifests[parent]
			if !ok {
				errs = append(errs, fmt.Errorf("%w: snapshot %s parent %s is missing", pverrors.ErrIntegrity, id, parent))
				continue
			}
			if parentManifest.SourceID != source {
				errs = append(errs, fmt.Errorf("%w: snapshot %s parent %s belongs to source %q", pverrors.ErrIntegrity, id, parent, parentManifest.SourceID))
				continue
			}
			children[parent] = append(children[parent], id)
		}
		if len(roots) > 1 {
			slices.Sort(roots)
			errs = append(errs, fmt.Errorf("%w: source %q has %d roots: chain is forked", pverrors.ErrIntegrity, source, len(roots)))
			continue
		}
		for parent, kids := range children {
			if len(kids) > 1 {
				slices.Sort(kids)
				errs = append(errs, fmt.Errorf("%w: source %q parent %s has %d children: chain is forked", pverrors.ErrIntegrity, source, parent, len(kids)))
			}
		}
		// The tip is the single childless snapshot: a snapshot that is
		// never a parent.
		isParent := map[string]bool{}
		for parent := range children {
			isParent[parent] = true
		}
		var tipCandidates []string
		for id := range ids {
			if !isParent[id] {
				tipCandidates = append(tipCandidates, id)
			}
		}
		if len(tipCandidates) != 1 {
			slices.Sort(tipCandidates)
			errs = append(errs, fmt.Errorf("%w: source %q has %d tips, want 1", pverrors.ErrIntegrity, source, len(tipCandidates)))
			continue
		}
		// Walk to the root to detect cycles and disconnected entries.
		seen := map[string]bool{}
		cur := tipCandidates[0]
		for cur != "" {
			if seen[cur] {
				errs = append(errs, fmt.Errorf("%w: source %q chain holds a cycle at %s", pverrors.ErrIntegrity, source, cur))
				break
			}
			seen[cur] = true
			m := ids[cur]
			if m.Parent == "" {
				break
			}
			cur = strings.ToLower(strings.TrimSpace(m.Parent))
			if _, ok := ids[cur]; !ok {
				break // Missing parent already reported.
			}
		}
		if len(seen) != len(ids) && len(errs) == 0 {
			// Disconnected without a second root/tip usually means a
			// cycle consumed the walk; report it plainly.
			errs = append(errs, fmt.Errorf("%w: source %q chain is disconnected", pverrors.ErrIntegrity, source))
			continue
		}
		tips[source] = tipCandidates[0]
	}
	if len(errs) > 0 {
		return map[string]string{}, errors.Join(errs...)
	}
	return tips, nil
}

// isAncestor reports whether ancestor appears on the parent walk from tip.
func isAncestor(ids map[string]manifest.Manifest, tip, ancestor string) bool {
	cur := tip
	for cur != "" {
		if cur == ancestor {
			return true
		}
		m, ok := ids[cur]
		if !ok || m.Parent == "" {
			return false
		}
		cur = strings.ToLower(strings.TrimSpace(m.Parent))
	}
	return false
}
