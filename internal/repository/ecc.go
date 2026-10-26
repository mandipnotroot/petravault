// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
)

// Object prefixes carrying parity sidecars (DESIGN.md §8). The literals match
// pack.PackPrefix, pack.IndexPrefix, and manifest.SnapshotPrefix; they are
// repeated here because pack and manifest already import this package, so
// importing them would cycle.
const (
	packPrefix     = "packs/"
	indexPrefix    = "indexes/"
	snapshotPrefix = "snapshots/"
)

// sidecarPrefixes lists the object families re-protected by Rebuild.
var sidecarPrefixes = []string{packPrefix, indexPrefix, snapshotPrefix}

// WriteSidecar encodes a parity sidecar for objectKey from its ciphertext
// bytes and stores it beside the object. Empty eccSetting selects the
// default; off writes nothing.
func WriteSidecar(ctx context.Context, repo Repository, objectKey string, objectBytes []byte, eccSetting string) error {
	if repo == nil {
		return errors.New("write sidecar: repository is nil")
	}
	params, err := erasure.Resolve(eccSetting)
	if err != nil {
		return err
	}
	if params.Off {
		return nil
	}
	sidecar, err := erasure.Encode(objectBytes, params)
	if err != nil {
		return err
	}
	if err := repo.PutObject(ctx, erasure.SidecarKey(objectKey), bytes.NewReader(sidecar)); err != nil {
		return fmt.Errorf("write sidecar for %s: %w", objectKey, err)
	}
	return nil
}

// RepairObject returns the object bytes repaired with its sidecar when one
// exists. A missing sidecar leaves the bytes untouched: normal reads never
// depend on sidecars (DESIGN.md §4.5). Repair failures wrap ErrUnrecoverable.
func RepairObject(ctx context.Context, repo Repository, objectKey string) ([]byte, error) {
	if repo == nil {
		return nil, errors.New("repair object: repository is nil")
	}
	raw, err := readKey(ctx, repo, objectKey)
	if err != nil {
		return nil, err
	}
	sidecarKey := erasure.SidecarKey(objectKey)
	exists, err := repo.Exists(ctx, sidecarKey)
	if err != nil {
		return nil, fmt.Errorf("stat sidecar for %s: %w", objectKey, err)
	}
	if !exists {
		return raw, nil
	}
	sidecar, err := readKey(ctx, repo, sidecarKey)
	if err != nil {
		return nil, err
	}
	fixed, err := erasure.Repair(raw, sidecar)
	if err != nil {
		return nil, fmt.Errorf("repair %s: %w", objectKey, err)
	}
	return fixed, nil
}

// Rebuild re-protects every pack, index, and snapshot with currentECC
// without touching the objects themselves: parity is computed over
// ciphertext (DESIGN.md §4.5). Each object is first repaired with its old
// sidecar when one exists, then AEAD-verified by verify applied to the
// repaired bytes, so damage is never encoded into fresh parity. Objects that
// fail repair or verification are left alone and reported; rebuilding to off
// removes sidecars. verify receives the object key and the repaired bytes
// and must return an error wrapping ErrIntegrity when they do not
// authenticate.
func Rebuild(ctx context.Context, repo Repository, currentECC string, verify func(objectKey string, objectBytes []byte) error) error {
	if repo == nil {
		return errors.New("rebuild erasure: repository is nil")
	}
	if verify == nil {
		return errors.New("rebuild erasure: verify is nil")
	}
	params, err := erasure.Resolve(currentECC)
	if err != nil {
		return err
	}
	var failed []error
	for _, prefix := range sidecarPrefixes {
		keys, err := repo.List(ctx, prefix)
		if err != nil {
			return fmt.Errorf("list %s: %w", prefix, err)
		}
		for _, key := range keys {
			if strings.HasSuffix(key, ".ecc") {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := rebuildOne(ctx, repo, key, params, verify); err != nil {
				failed = append(failed, err)
			}
		}
	}
	return errors.Join(failed...)
}

func rebuildOne(ctx context.Context, repo Repository, objectKey string, params erasure.Params, verify func(string, []byte) error) error {
	stored, err := readKey(ctx, repo, objectKey)
	if err != nil {
		return fmt.Errorf("rebuild %s: %w", objectKey, err)
	}
	repaired := stored
	sidecarKey := erasure.SidecarKey(objectKey)
	if exists, err := repo.Exists(ctx, sidecarKey); err != nil {
		return fmt.Errorf("rebuild %s: stat sidecar: %w", objectKey, err)
	} else if exists {
		old, err := readKey(ctx, repo, sidecarKey)
		if err != nil {
			return fmt.Errorf("rebuild %s: %w", objectKey, err)
		}
		fixed, err := erasure.Repair(stored, old)
		if err != nil {
			return fmt.Errorf("rebuild %s: %w", objectKey, err)
		}
		repaired = fixed
	}
	if err := verify(objectKey, repaired); err != nil {
		return fmt.Errorf("rebuild %s: refusing to encode unverified data: %w", objectKey, err)
	}
	// Rebuild changes sidecars only. An in-memory repair does not make the
	// durable ciphertext independent of its old recovery material.
	if !bytes.Equal(stored, repaired) {
		return fmt.Errorf("%w: rebuild %s: stored object requires repair; preserving its sidecar", pverrors.ErrIntegrity, objectKey)
	}
	if params.Off {
		if err := repo.DeleteObject(ctx, sidecarKey); err != nil {
			return fmt.Errorf("rebuild %s: remove sidecar: %w", objectKey, err)
		}
		return nil
	}
	fresh, err := erasure.Encode(repaired, params)
	if err != nil {
		return fmt.Errorf("rebuild %s: %w", objectKey, err)
	}
	if err := repo.PutObject(ctx, sidecarKey, bytes.NewReader(fresh)); err != nil {
		return fmt.Errorf("rebuild %s: write sidecar: %w", objectKey, err)
	}
	return nil
}

func readKey(ctx context.Context, repo Repository, key string) ([]byte, error) {
	raw, err := ReadObject(ctx, repo, key)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return raw, nil
}
