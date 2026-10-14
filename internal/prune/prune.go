// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package prune implements retention and garbage collection (DESIGN.md
// §11.3, §10.2). Retention selects snapshots to keep with per-source
// daily/weekly/monthly buckets plus the newest snapshot of every source,
// which is always kept. Garbage collection deletes pruned snapshots,
// packs whose chunks are all unreferenced, and old indexes; packs that are
// mostly unreferenced are repacked without their dead chunks under the
// current erasure setting, and indexes are compacted to one object.
//
// Pruned history creates gaps in per-source parent chains: a retained
// snapshot whose parent was pruned becomes a new root. Chain checks in this
// package therefore allow missing parents and multiple roots while still
// rejecting forks (two retained children of one parent), cross-source
// parents, cycles, and multiple tips. Rollback of the newest snapshot is
// still detected via client-local head records in verify (DESIGN.md §9).
// Deletion of old history via prune is legitimate maintenance, not an
// attack: the attack table (§13) requires detection of newest-snapshot
// deletion, not of intermediate history removal.
package prune

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"petravault/internal/compression"
	"petravault/internal/crypto"
	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
	"petravault/internal/manifest"
	"petravault/internal/pack"
	"petravault/internal/repository"
)

// RepackThreshold is the fraction of dead chunks that triggers a repack.
// Packs with all chunks dead are deleted; packs with at least this fraction
// dead are rewritten without the dead chunks; the rest are kept as-is.
// A chunk cannot be deleted individually from a pack (DESIGN.md §11.3).
const RepackThreshold = 0.5

// Retention selects snapshots to keep. Each field counts distinct buckets
// to keep per source; zero disables that bucket. At least one field must be
// positive: prune refuses to run without a keep rule (DESIGN.md §11.3).
type Retention struct {
	Daily   int
	Weekly  int
	Monthly int
}

// Validate rejects negative counts and the empty rule set.
func (r Retention) Validate() error {
	if r.Daily < 0 || r.Weekly < 0 || r.Monthly < 0 {
		return fmt.Errorf("%w: retention counts must not be negative", pverrors.ErrUsage)
	}
	if r.Daily == 0 && r.Weekly == 0 && r.Monthly == 0 {
		return fmt.Errorf("%w: prune needs at least one keep rule (--keep-daily, --keep-weekly, --keep-monthly)", pverrors.ErrUsage)
	}
	return nil
}

// SnapshotInfo carries the fields retention needs.
type SnapshotInfo struct {
	ID        string
	SourceID  string
	CreatedAt time.Time
}

// Options configures one prune run.
type Options struct {
	// Retention selects snapshots to keep. It must validate.
	Retention Retention
	// DryRun previews deletions and repacks without writing or deleting
	// anything.
	DryRun bool
	// RepackThreshold overrides RepackThreshold for tests. Non-positive
	// selects the default.
	RepackThreshold float64
	// MaxChunkSize caps decompression of any single chunk during repack.
	// Non-positive selects the repository maximum.
	MaxChunkSize int
	// Logger receives progress. Nil discards logs.
	Logger *slog.Logger
}

// Report summarizes one prune run. Lists hold sorted repository keys or
// snapshot IDs; NewIndex is empty when no index was written (no referenced
// chunks or dry run).
type Report struct {
	Retained         []string
	DeletedSnapshots []string
	DeletedPacks     []string
	RepackedPacks    []string
	NewPacks         []string
	DeletedIndexes   []string
	NewIndex         string
	DryRun           bool
}

// SelectRetained returns the IDs to keep: the newest snapshot of every
// source plus the newest snapshot per UTC day/week/month for the last N
// distinct buckets per source. Input order is ignored; output is a set.
func SelectRetained(infos []SnapshotInfo, r Retention) (map[string]bool, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	bySource := make(map[string][]SnapshotInfo)
	for _, info := range infos {
		if strings.TrimSpace(info.ID) == "" || strings.TrimSpace(info.SourceID) == "" {
			return nil, fmt.Errorf("%w: snapshot info holds an empty id or source", pverrors.ErrUsage)
		}
		bySource[info.SourceID] = append(bySource[info.SourceID], info)
	}
	kept := make(map[string]bool)
	for _, group := range bySource {
		sorted := slices.Clone(group)
		slices.SortFunc(sorted, func(a, b SnapshotInfo) int {
			if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
				return c
			}
			return cmp.Compare(a.ID, b.ID)
		})
		if len(sorted) == 0 {
			continue
		}
		kept[sorted[0].ID] = true
		keepBucket(sorted, kept, r.Daily, dailyKey)
		keepBucket(sorted, kept, r.Weekly, weeklyKey)
		keepBucket(sorted, kept, r.Monthly, monthlyKey)
	}
	return kept, nil
}

func dailyKey(t time.Time) string {
	y, m, d := t.UTC().Date()
	return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
}

func weeklyKey(t time.Time) string {
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%04d-W%02d", y, w)
}

func monthlyKey(t time.Time) string {
	y, m, _ := t.UTC().Date()
	return fmt.Sprintf("%04d-%02d", y, m)
}

// keepBucket retains the newest snapshot per distinct bucket key for the
// first n buckets in time-descending order. sorted must already be newest
// first.
func keepBucket(sorted []SnapshotInfo, kept map[string]bool, n int, key func(time.Time) string) {
	if n <= 0 {
		return
	}
	seen := make(map[string]bool)
	buckets := 0
	for _, info := range sorted {
		k := key(info.CreatedAt)
		if seen[k] {
			continue
		}
		seen[k] = true
		buckets++
		if buckets > n {
			return
		}
		kept[info.ID] = true
	}
}

// Prune runs retention and garbage collection. The caller must hold
// locks/gc.lock (see repository.TryAcquireGCLock and WaitForBackups);
// Prune itself performs no locking so unit tests can run it directly.
// lookup resolves a snapshot signer's public key from its identity hint
// against the client-local trust list, like verify does. Any integrity
// failure aborts before anything is deleted: prune never deletes under
// doubt. Dry runs read everything but write and delete nothing.
func Prune(ctx context.Context, repo repository.Repository, repoCfg repository.Config, dataKey, chunkIDKey crypto.SecretKey, lookup func(string) ([]byte, error), opts Options) (Report, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	var report Report
	report.DryRun = opts.DryRun
	if repo == nil {
		return report, errors.New("prune: repository is nil")
	}
	if lookup == nil {
		return report, errors.New("prune: lookup is nil")
	}
	if err := repoCfg.Validate(); err != nil {
		return report, err
	}
	if err := opts.Retention.Validate(); err != nil {
		return report, err
	}
	threshold := opts.RepackThreshold
	if threshold <= 0 {
		threshold = RepackThreshold
	}
	if threshold <= 0 || threshold > 1 {
		return report, fmt.Errorf("%w: invalid repack threshold %v", pverrors.ErrUsage, opts.RepackThreshold)
	}
	maxChunk := opts.MaxChunkSize
	if maxChunk <= 0 {
		maxChunk = repoCfg.ChunkMax
	}
	if maxChunk <= 0 {
		maxChunk = compression.DefaultMaxSize
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}

	ids, err := manifest.List(ctx, repo)
	if err != nil {
		return report, err
	}
	if len(ids) == 0 {
		return report, nil
	}
	manifests := make(map[string]manifest.Manifest, len(ids))
	infos := make([]SnapshotInfo, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		m, err := manifest.OpenTrusted(ctx, repo, repoCfg.RepositoryID, dataKey, id, lookup)
		if err != nil {
			return report, fmt.Errorf("prune snapshot %s: %w", id, err)
		}
		if m.CryptoSuite != repoCfg.CryptoSuite {
			return report, fmt.Errorf("%w: snapshot %s names crypto suite %q, want %q", pverrors.ErrIntegrity, id, m.CryptoSuite, repoCfg.CryptoSuite)
		}
		if m.ChunkingAlgorithm != repoCfg.ChunkingAlgorithm {
			return report, fmt.Errorf("%w: snapshot %s names chunking %q, want %q", pverrors.ErrIntegrity, id, m.ChunkingAlgorithm, repoCfg.ChunkingAlgorithm)
		}
		manifests[id] = m
		infos = append(infos, SnapshotInfo{ID: id, SourceID: m.SourceID, CreatedAt: m.CreatedAt})
	}
	if err := checkPruneChains(manifests); err != nil {
		return report, err
	}
	kept, err := SelectRetained(infos, opts.Retention)
	if err != nil {
		return report, err
	}
	// Prune never removes the most recent snapshot of any source: tips
	// are always kept even if bucket math missed them (e.g. clock skew).
	for _, tip := range pruneTips(manifests) {
		kept[tip] = true
	}
	for id := range manifests {
		if kept[id] {
			report.Retained = append(report.Retained, id)
		} else {
			report.DeletedSnapshots = append(report.DeletedSnapshots, id)
		}
	}
	slices.Sort(report.Retained)
	slices.Sort(report.DeletedSnapshots)

	referenced := make(map[[32]byte]bool)
	for id, m := range manifests {
		if !kept[id] {
			continue
		}
		for _, f := range m.Files {
			for _, chunkHex := range f.Chunks {
				chunkID, err := pack.ParseID(chunkHex)
				if err != nil {
					return report, fmt.Errorf("%w: snapshot %s file %q holds %w", pverrors.ErrIntegrity, id, f.Path, err)
				}
				referenced[chunkID] = true
			}
		}
	}

	merged, err := pack.LoadEntries(ctx, repo, repoCfg.RepositoryID, dataKey)
	if err != nil {
		return report, fmt.Errorf("prune indexes: %w", err)
	}
	packKeys, err := listPacks(ctx, repo)
	if err != nil {
		return report, err
	}
	packRefs := make(map[string][]pack.Entry, len(packKeys))
	for _, key := range packKeys {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		entries, err := pack.ListPackEntries(ctx, repo, repoCfg.RepositoryID, dataKey, key)
		if err != nil {
			return report, fmt.Errorf("prune pack %s: %w", key, err)
		}
		packRefs[key] = entries
	}
	// Every referenced chunk must resolve to at least one pack before
	// anything is deleted; otherwise abort without deleting.
	for id := range referenced {
		found := false
		for _, entries := range packRefs {
			for _, e := range entries {
				if e.ID == id {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			// Fall back to the merged index (e.g. a pack was already
			// deleted but its index entry remains): still missing means
			// the snapshot references a chunk with no pack.
			if _, ok := merged[id]; !ok {
				return report, fmt.Errorf("%w: retained snapshots reference missing chunk %s", pverrors.ErrIntegrity, pack.FormatID(id))
			}
		}
	}

	var keepPacks, deletePacks, repackPacks []string
	for _, key := range packKeys {
		entries := packRefs[key]
		if len(entries) == 0 {
			deletePacks = append(deletePacks, key)
			continue
		}
		live := 0
		for _, e := range entries {
			if referenced[e.ID] {
				live++
			}
		}
		switch {
		case live == 0:
			deletePacks = append(deletePacks, key)
		case float64(len(entries)-live)/float64(len(entries)) >= threshold:
			repackPacks = append(repackPacks, key)
		default:
			keepPacks = append(keepPacks, key)
		}
	}
	slices.Sort(keepPacks)
	slices.Sort(deletePacks)
	slices.Sort(repackPacks)

	// Kept chunks seed repack dedup: live chunks already in kept packs
	// are not rewritten from repacked packs.
	keptChunks := make(map[[32]byte]bool)
	for _, key := range keepPacks {
		for _, e := range packRefs[key] {
			if referenced[e.ID] {
				keptChunks[e.ID] = true
			}
		}
	}
	type repackItem struct {
		id [32]byte
	}
	var toRepack []repackItem
	seenRepack := make(map[[32]byte]bool)
	for _, key := range repackPacks {
		for _, e := range packRefs[key] {
			if !referenced[e.ID] || keptChunks[e.ID] || seenRepack[e.ID] {
				continue
			}
			seenRepack[e.ID] = true
			toRepack = append(toRepack, repackItem{id: e.ID})
		}
	}
	// Deterministic repack order.
	slices.SortFunc(toRepack, func(a, b repackItem) int {
		return bytes.Compare(a.id[:], b.id[:])
	})

	var newPacks []string
	var newEntries []pack.Entry
	if len(toRepack) > 0 {
		writer := pack.NewWriter(repoCfg.RepositoryID, dataKey, repoCfg.PackSize)
		// Dry runs verify readability without writing new packs.
		for _, item := range toRepack {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			loc, ok := merged[item.id]
			if !ok {
				return report, fmt.Errorf("%w: chunk %s has no index entry for repack", pverrors.ErrIntegrity, pack.FormatID(item.id))
			}
			plaintext, err := pack.ReadChunk(ctx, repo, repoCfg.RepositoryID, dataKey, chunkIDKey, loc, maxChunk)
			if err != nil {
				return report, fmt.Errorf("repack chunk %s: %w", pack.FormatID(item.id), err)
			}
			if opts.DryRun {
				continue
			}
			if err := writer.Add(item.id, plaintext); err != nil {
				return report, fmt.Errorf("repack chunk %s: %w", pack.FormatID(item.id), err)
			}
			if writer.Buffered() >= repoCfg.PackSize {
				key, err := writer.Flush(ctx, repo, repoCfg.ECC)
				if err != nil {
					return report, err
				}
				if key != "" {
					newPacks = append(newPacks, key)
				}
			}
		}
		if !opts.DryRun {
			// Flush the tail and collect entries for the new index.
			tail, err := writer.Flush(ctx, repo, repoCfg.ECC)
			if err != nil {
				return report, err
			}
			if tail != "" {
				newPacks = append(newPacks, tail)
			}
			newEntries = writer.Entries()
		}
	}
	slices.Sort(newPacks)

	// Final index entries come from authoritative pack contents (kept
	// packs) plus repacked blobs, deduped deterministically. Stored index
	// offsets are never trusted for kept packs.
	finalByID := make(map[[32]byte]pack.Entry)
	for _, key := range keepPacks {
		for _, e := range packRefs[key] {
			if !referenced[e.ID] {
				continue
			}
			if _, ok := finalByID[e.ID]; !ok {
				finalByID[e.ID] = e
			}
		}
	}
	for _, e := range newEntries {
		if _, ok := finalByID[e.ID]; !ok {
			finalByID[e.ID] = e
		}
	}
	// Dry runs would write new packs for toRepack IDs; count them as
	// surviving without requiring newEntries.
	if opts.DryRun {
		for _, item := range toRepack {
			if _, ok := finalByID[item.id]; !ok {
				finalByID[item.id] = pack.Entry{ID: item.id, Pack: "(new pack, dry run)"}
			}
		}
	}
	for id := range referenced {
		if _, ok := finalByID[id]; !ok {
			return report, fmt.Errorf("%w: chunk %s has no surviving location after repack plan", pverrors.ErrIntegrity, pack.FormatID(id))
		}
	}
	finalEntries := make([]pack.Entry, 0, len(finalByID))
	for _, e := range finalByID {
		finalEntries = append(finalEntries, e)
	}
	slices.SortFunc(finalEntries, func(a, b pack.Entry) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	oldIndexes, err := pack.ListIndexKeys(ctx, repo)
	if err != nil {
		return report, fmt.Errorf("prune indexes: %w", err)
	}
	slices.Sort(oldIndexes)

	report.DeletedPacks = append(report.DeletedPacks, deletePacks...)
	report.DeletedPacks = append(report.DeletedPacks, repackPacks...)
	slices.Sort(report.DeletedPacks)
	report.RepackedPacks = slices.Clone(repackPacks)
	report.NewPacks = newPacks
	report.DeletedIndexes = slices.Clone(oldIndexes)

	if opts.DryRun {
		logger.InfoContext(ctx, "prune dry run",
			slog.Int("retained", len(report.Retained)),
			slog.Int("deleted_snapshots", len(report.DeletedSnapshots)),
			slog.Int("deleted_packs", len(report.DeletedPacks)),
			slog.Int("repacked_packs", len(report.RepackedPacks)))
		return report, nil
	}

	// Crash safety: the compacted index is written before any deletion, so
	// a crash between the two leaves duplicate indexes (harmless: clients
	// merge them) rather than live chunks with no index. New packs were
	// already written during repack planning above.
	var newIndex string
	if len(finalEntries) > 0 {
		indexKey, err := pack.WriteIndex(ctx, repo, repoCfg.RepositoryID, dataKey, finalEntries, repoCfg.ECC)
		if err != nil {
			return report, fmt.Errorf("compact indexes: %w", err)
		}
		newIndex = indexKey
	}
	report.NewIndex = newIndex
	for _, id := range report.DeletedSnapshots {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := repo.DeleteObject(ctx, manifest.SnapshotPrefix+id); err != nil {
			return report, fmt.Errorf("delete snapshot %s: %w", id, err)
		}
		if err := repo.DeleteObject(ctx, erasure.SidecarKey(manifest.SnapshotPrefix+id)); err != nil {
			return report, fmt.Errorf("delete snapshot sidecar %s: %w", id, err)
		}
	}
	for _, key := range report.DeletedPacks {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := repo.DeleteObject(ctx, key); err != nil {
			return report, fmt.Errorf("delete pack %s: %w", key, err)
		}
		if err := repo.DeleteObject(ctx, erasure.SidecarKey(key)); err != nil {
			return report, fmt.Errorf("delete pack sidecar %s: %w", key, err)
		}
	}
	for _, key := range oldIndexes {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		// Never delete the index just written: it may sort among the old
		// keys when no repack occurred and the content is unchanged.
		if key == newIndex {
			continue
		}
		if err := repo.DeleteObject(ctx, key); err != nil {
			return report, fmt.Errorf("delete index %s: %w", key, err)
		}
		if err := repo.DeleteObject(ctx, erasure.SidecarKey(key)); err != nil {
			return report, fmt.Errorf("delete index sidecar %s: %w", key, err)
		}
	}
	logger.InfoContext(ctx, "prune finished",
		slog.Int("retained", len(report.Retained)),
		slog.Int("deleted_snapshots", len(report.DeletedSnapshots)),
		slog.Int("deleted_packs", len(report.DeletedPacks)),
		slog.Int("repacked_packs", len(report.RepackedPacks)),
		slog.String("new_index", report.NewIndex))
	return report, nil
}

func listPacks(ctx context.Context, repo repository.Repository) ([]string, error) {
	keys, err := repo.List(ctx, pack.PackPrefix)
	if err != nil {
		return nil, fmt.Errorf("list packs: %w", err)
	}
	out := keys[:0]
	for _, k := range keys {
		if strings.HasSuffix(k, ".ecc") {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// pruneTips returns each source's childless snapshot. Multiple childless
// snapshots for one source are a fork and fail closed.
func pruneTips(manifests map[string]manifest.Manifest) []string {
	bySource := make(map[string][]string)
	for id, m := range manifests {
		bySource[m.SourceID] = append(bySource[m.SourceID], id)
	}
	var tips []string
	for _, ids := range bySource {
		isParent := make(map[string]bool)
		for _, id := range ids {
			parent := strings.ToLower(strings.TrimSpace(manifests[id].Parent))
			if parent != "" {
				if _, ok := manifests[parent]; ok {
					isParent[parent] = true
				}
			}
		}
		for _, id := range ids {
			if !isParent[id] {
				tips = append(tips, id)
			}
		}
	}
	slices.Sort(tips)
	return tips
}

// checkPruneChains validates per-source parent links with pruned-history
// tolerance: missing parents and multiple roots are allowed (they are new
// roots after prune), but forks (two retained children of one parent),
// cross-source parents, cycles, and multiple tips still fail closed.
func checkPruneChains(manifests map[string]manifest.Manifest) error {
	bySource := make(map[string]map[string]manifest.Manifest)
	for id, m := range manifests {
		if bySource[m.SourceID] == nil {
			bySource[m.SourceID] = make(map[string]manifest.Manifest)
		}
		bySource[m.SourceID][id] = m
	}
	var errs []error
	for source, ids := range bySource {
		children := make(map[string][]string)
		for id, m := range ids {
			if m.Parent == "" {
				continue
			}
			parent := strings.ToLower(strings.TrimSpace(m.Parent))
			parentManifest, ok := manifests[parent]
			if !ok {
				// Pruned history: the parent is gone, this snapshot is
				// a new root. Not an error.
				continue
			}
			if parentManifest.SourceID != source {
				errs = append(errs, fmt.Errorf("%w: snapshot %s parent %s belongs to source %q", pverrors.ErrIntegrity, id, parent, parentManifest.SourceID))
				continue
			}
			children[parent] = append(children[parent], id)
		}
		for parent, kids := range children {
			if len(kids) > 1 {
				slices.Sort(kids)
				errs = append(errs, fmt.Errorf("%w: source %q parent %s has %d children: chain is forked", pverrors.ErrIntegrity, source, parent, len(kids)))
			}
		}
		isParent := make(map[string]bool)
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
		// Walk to the root, stopping at pruned gaps, to detect cycles.
		seen := make(map[string]bool)
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
			parent := strings.ToLower(strings.TrimSpace(m.Parent))
			if _, ok := ids[parent]; !ok {
				break // Pruned gap: new root.
			}
			cur = parent
		}
	}
	return errors.Join(errs...)
}
