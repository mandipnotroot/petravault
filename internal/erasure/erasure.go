// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package erasure implements Reed-Solomon parity sidecars (DESIGN.md §4.5).
// Parity is systematic and per object, computed over ciphertext: the object
// is stored unchanged and a single sidecar "<object>.ecc" holds the parity
// shards plus a BLAKE3 checksum of every data shard and the parameters used.
// Normal reads never touch the sidecar. Damaged shards are identified by
// their checksums (they become known erasures), reconstructed, and the
// result must be re-verified by AEAD before use; Reed-Solomon recovers
// erasures and is never a substitute for cryptographic integrity.
package erasure

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	json "encoding/json/v2"

	"github.com/klauspost/reedsolomon"

	"petravault/internal/crypto"
	pverrors "petravault/internal/errors"
)

// Version is the sidecar format version.
const Version = 1

// MaxShards bounds k+m to the Reed-Solomon limit (DESIGN.md §4.5).
const MaxShards = 255

// Overhead bounds for custom percentages in basis points (DESIGN.md §4.5).
// 0.5% is 50 bps, 100% is 10000 bps.
const (
	MinOverheadBPS = 50
	MaxOverheadBPS = 10000
)

// Named profile overheads in basis points (DESIGN.md §4.5). The names are
// frozen shorthand; repair never depends on the name since each sidecar
// records its own k and m.
const (
	LowOverheadBPS    = 200
	MediumOverheadBPS = 500
	HighOverheadBPS   = 1500
)

// Params describes one erasure setting: the requested overhead and the
// derived shard counts. Integer basis points carry the percentage (5% is
// 500) so floating-point rounding cannot change k or m (DESIGN.md §4.5).
type Params struct {
	// Setting is the normalized input ("off", "low", "medium", "high",
	// or "<N>%").
	Setting string
	// OverheadBPS is the requested overhead in basis points (0 when off).
	OverheadBPS int
	// K is the data shard count, M the parity shard count (0 when off).
	K int
	M int
	// Off disables erasure coding.
	Off bool
}

// Parse accepts off, a named profile, or a custom percentage and derives k
// and m with integer math (DESIGN.md §4.5):
//
//	m = max(1, floor(overhead x 20))
//	k = floor(m / overhead)
//	effective overhead = m / k
//
// Custom percentages range from 0.5% to 100% with at most two decimal
// places; k+m must stay within MaxShards. Failures wrap ErrUsage.
func Parse(s string) (Params, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: want off, low, medium, high, or <N>%%", pverrors.ErrUsage, s)
	}
	lower := strings.ToLower(t)
	switch lower {
	case "off":
		return Params{Setting: "off", Off: true}, nil
	case "low":
		return derive("low", LowOverheadBPS)
	case "medium":
		return derive("medium", MediumOverheadBPS)
	case "high":
		return derive("high", HighOverheadBPS)
	}
	v, ok := strings.CutSuffix(t, "%")
	if !ok || strings.TrimSpace(v) == "" {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: want off, low, medium, high, or <N>%%", pverrors.ErrUsage, s)
	}
	v = strings.TrimSpace(v)
	bps, err := percentToBPS(v)
	if err != nil {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: %w", pverrors.ErrUsage, s, err)
	}
	if bps < MinOverheadBPS || bps > MaxOverheadBPS {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: overhead must be 0.5%%..100%%", pverrors.ErrUsage, s)
	}
	// Normalize the setting: strip spaces, keep the numeric form.
	setting := v + "%"
	return derive(setting, bps)
}

func derive(setting string, bps int) (Params, error) {
	m := max(1, bps/500)
	k := m * 10000 / bps
	if k < 1 {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: derived no data shards", pverrors.ErrUsage, setting)
	}
	if k+m > MaxShards {
		return Params{}, fmt.Errorf("%w: invalid ecc %q: %d shards exceed the %d limit", pverrors.ErrUsage, setting, k+m, MaxShards)
	}
	return Params{Setting: setting, OverheadBPS: bps, K: k, M: m}, nil
}

// percentToBPS converts a numeric percentage without the "%" suffix to basis
// points using integer math only. At most two fractional digits are accepted
// so every input maps to an exact integer.
func percentToBPS(v string) (int, error) {
	intPart, fracPart, found := strings.Cut(v, ".")
	if !found {
		n, err := atoi(v)
		if err != nil {
			return 0, err
		}
		return n * 100, nil
	}
	// A second dot is invalid.
	if strings.Contains(fracPart, ".") {
		return 0, errors.New("want at most two decimal places")
	}
	if intPart == "" || fracPart == "" || len(fracPart) > 2 {
		return 0, errors.New("want <N>% with at most two decimal places")
	}
	n, err := atoi(intPart)
	if err != nil {
		return 0, err
	}
	// Pad one fractional digit ("7.5" -> "50") to basis points.
	padded := fracPart
	if len(padded) == 1 {
		padded += "0"
	}
	f, err := atoi(padded)
	if err != nil {
		return 0, err
	}
	return n*100 + f, nil
}

func atoi(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty number")
	}
	// Percentages are small (0.5%..100%); a long digit run is a typo, not
	// a setting, and bounds the n*10 accumulation below.
	if len(s) > 6 {
		return 0, fmt.Errorf("invalid number %q: too many digits", s)
	}
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid number %q", s)
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, nil
}

// Effective returns the effective overhead ("5.0%") derived from m/k, always
// greater than or equal to the requested value (DESIGN.md §4.5). It is
// display only; k and m derivation never uses floats.
func (p Params) Effective() string {
	if p.Off {
		return "off"
	}
	tenths := p.M * 1000 / p.K
	return fmt.Sprintf("%d.%d%%", tenths/10, tenths%10)
}

// Describe reports the setting with its effective overhead and shard counts
// for init and info output (DESIGN.md §4.5).
func (p Params) Describe() string {
	if p.Off {
		return "off"
	}
	return fmt.Sprintf("%s (effective %s, k=%d, m=%d)", p.Setting, p.Effective(), p.K, p.M)
}

// Default returns the default medium profile.
func Default() Params {
	p, err := Parse("medium")
	if err != nil {
		panic("default erasure params must parse")
	}
	return p
}

// Resolve returns the params for s, defaulting empty input to medium.
func Resolve(s string) (Params, error) {
	return Parse(cmp.Or(strings.TrimSpace(s), "medium"))
}

// SidecarKey returns the sidecar object key beside objectKey.
func SidecarKey(objectKey string) string {
	return objectKey + ".ecc"
}

// Sidecar is the wire form of a parity sidecar. Checksums are hex BLAKE3 of
// each data shard; Parity holds each parity shard (JSON base64). Field order
// is fixed so the stored bytes are deterministic for given inputs.
type Sidecar struct {
	Version    int      `json:"version"`
	Algorithm  string   `json:"algorithm"`
	K          int      `json:"k"`
	M          int      `json:"m"`
	DataLength int      `json:"data_length"`
	Checksums  []string `json:"checksums,omitempty"`
	Parity     [][]byte `json:"parity,omitempty"`
}

// ShardSize returns the equal shard size for dataLen bytes across k shards.
func ShardSize(dataLen, k int) int {
	return (dataLen + k - 1) / k
}

// Encode splits data into p.K equal shards (zero-padded), computes m parity
// shards over the ciphertext, checksums every data shard, and returns the
// marshaled sidecar. Off is refused: callers skip sidecars when disabled.
func Encode(data []byte, p Params) ([]byte, error) {
	if p.Off {
		return nil, fmt.Errorf("%w: refusing to encode erasure sidecar for off", pverrors.ErrUsage)
	}
	if p.K < 1 || p.M < 1 || p.K+p.M > MaxShards {
		return nil, fmt.Errorf("%w: invalid erasure params k=%d m=%d", pverrors.ErrUsage, p.K, p.M)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: refusing to encode an empty object", pverrors.ErrUsage)
	}
	enc, err := reedsolomon.New(p.K, p.M)
	if err != nil {
		return nil, fmt.Errorf("create encoder: %w", err)
	}
	size := ShardSize(len(data), p.K)
	padded := make([]byte, size*p.K)
	copy(padded, data)
	shards := make([][]byte, p.K+p.M)
	for i := range p.K {
		shards[i] = padded[i*size : (i+1)*size]
	}
	for i := range p.M {
		shards[p.K+i] = make([]byte, size)
	}
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encode parity: %w", err)
	}
	sc := Sidecar{
		Version:    Version,
		Algorithm:  crypto.ErasureID,
		K:          p.K,
		M:          p.M,
		DataLength: len(data),
	}
	for _, d := range shards[:p.K] {
		sum := crypto.Sum256(d)
		sc.Checksums = append(sc.Checksums, hex.EncodeToString(sum[:]))
	}
	for _, q := range shards[p.K:] {
		sc.Parity = append(sc.Parity, bytes.Clone(q))
	}
	raw, err := json.Marshal(sc)
	if err != nil {
		return nil, fmt.Errorf("marshal sidecar: %w", err)
	}
	return raw, nil
}

// Decode parses and validates sidecar bytes from untrusted storage.
func Decode(raw []byte) (Sidecar, error) {
	var sc Sidecar
	if err := json.Unmarshal(raw, &sc, json.RejectUnknownMembers(true)); err != nil {
		return Sidecar{}, fmt.Errorf("decode sidecar: %w", err)
	}
	if sc.Version != Version {
		return Sidecar{}, fmt.Errorf("sidecar has version %d, want %d", sc.Version, Version)
	}
	if sc.Algorithm != crypto.ErasureID {
		return Sidecar{}, fmt.Errorf("%w: sidecar names algorithm %q, want %q", pverrors.ErrIntegrity, sc.Algorithm, crypto.ErasureID)
	}
	if sc.K < 1 || sc.M < 1 || sc.K+sc.M > MaxShards {
		return Sidecar{}, fmt.Errorf("%w: sidecar holds invalid shards k=%d m=%d", pverrors.ErrIntegrity, sc.K, sc.M)
	}
	if sc.DataLength <= 0 {
		return Sidecar{}, fmt.Errorf("%w: sidecar holds an invalid data length", pverrors.ErrIntegrity)
	}
	if len(sc.Checksums) != sc.K {
		return Sidecar{}, fmt.Errorf("%w: sidecar holds %d checksums, want %d", pverrors.ErrIntegrity, len(sc.Checksums), sc.K)
	}
	for _, c := range sc.Checksums {
		rawSum, err := hex.DecodeString(c)
		if err != nil || len(rawSum) != crypto.HashLength {
			return Sidecar{}, fmt.Errorf("%w: sidecar holds an invalid checksum", pverrors.ErrIntegrity)
		}
	}
	if len(sc.Parity) != sc.M {
		return Sidecar{}, fmt.Errorf("%w: sidecar holds %d parity shards, want %d", pverrors.ErrIntegrity, len(sc.Parity), sc.M)
	}
	size := ShardSize(sc.DataLength, sc.K)
	for _, q := range sc.Parity {
		if len(q) != size {
			return Sidecar{}, fmt.Errorf("%w: sidecar holds a mis-sized parity shard", pverrors.ErrIntegrity)
		}
	}
	return sc, nil
}

// Verify reports whether data matches its sidecar: every data-shard checksum
// and the parity set. Mismatches wrap ErrUnrecoverable (exit code 4).
func Verify(data, sidecarBytes []byte) error {
	sc, err := Decode(sidecarBytes)
	if err != nil {
		return err
	}
	if len(data) != sc.DataLength {
		return fmt.Errorf("%w: object size %d disagrees with its sidecar %d", pverrors.ErrUnrecoverable, len(data), sc.DataLength)
	}
	size := ShardSize(len(data), sc.K)
	padded := make([]byte, size*sc.K)
	copy(padded, data)
	for i := range sc.K {
		sum := crypto.Sum256(padded[i*size : (i+1)*size])
		want, err := hex.DecodeString(sc.Checksums[i])
		if err != nil {
			return fmt.Errorf("%w: sidecar holds an invalid checksum", pverrors.ErrIntegrity)
		}
		if !bytes.Equal(sum[:], want) {
			return fmt.Errorf("%w: shard %d checksum mismatch", pverrors.ErrUnrecoverable, i)
		}
	}
	enc, err := reedsolomon.New(sc.K, sc.M)
	if err != nil {
		return fmt.Errorf("create encoder: %w", err)
	}
	shards := make([][]byte, sc.K+sc.M)
	for i := range sc.K {
		shards[i] = padded[i*size : (i+1)*size]
	}
	for i := range sc.M {
		shards[sc.K+i] = sc.Parity[i]
	}
	ok, err := enc.Verify(shards)
	if err != nil {
		return fmt.Errorf("verify parity: %w", err)
	}
	if !ok {
		return fmt.Errorf("%w: parity mismatch", pverrors.ErrUnrecoverable)
	}
	return nil
}

// Repair reconstructs data damaged within its parity budget. Checksums mark
// the damaged data shards as known erasures; at most m may be damaged. Intact
// input returns a clone. Damage beyond the budget wraps ErrUnrecoverable and
// yields no repaired output. Callers must still AEAD-verify the result.
func Repair(data, sidecarBytes []byte) ([]byte, error) {
	sc, err := Decode(sidecarBytes)
	if err != nil {
		return nil, err
	}
	if len(data) != sc.DataLength {
		return nil, fmt.Errorf("%w: object size %d disagrees with its sidecar %d", pverrors.ErrUnrecoverable, len(data), sc.DataLength)
	}
	size := ShardSize(len(data), sc.K)
	padded := make([]byte, size*sc.K)
	copy(padded, data)
	var bad []int
	for i := range sc.K {
		sum := crypto.Sum256(padded[i*size : (i+1)*size])
		want, err := hex.DecodeString(sc.Checksums[i])
		if err != nil {
			return nil, fmt.Errorf("%w: sidecar holds an invalid checksum", pverrors.ErrIntegrity)
		}
		if !bytes.Equal(sum[:], want) {
			bad = append(bad, i)
		}
	}
	if len(bad) == 0 {
		return bytes.Clone(data), nil
	}
	if len(bad) > sc.M {
		return nil, fmt.Errorf("%w: %d damaged shards exceed the %d-shard budget", pverrors.ErrUnrecoverable, len(bad), sc.M)
	}
	enc, err := reedsolomon.New(sc.K, sc.M)
	if err != nil {
		return nil, fmt.Errorf("create encoder: %w", err)
	}
	shards := make([][]byte, sc.K+sc.M)
	for i := range sc.K {
		if slices.Contains(bad, i) {
			shards[i] = nil
		} else {
			shards[i] = padded[i*size : (i+1)*size]
		}
	}
	for i := range sc.M {
		shards[sc.K+i] = bytes.Clone(sc.Parity[i])
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil, fmt.Errorf("%w: reconstruct: %w", pverrors.ErrUnrecoverable, err)
	}
	for _, i := range bad {
		if len(shards[i]) != size {
			return nil, fmt.Errorf("%w: reconstruction produced a mis-sized shard", pverrors.ErrUnrecoverable)
		}
		sum := crypto.Sum256(shards[i])
		want, err := hex.DecodeString(sc.Checksums[i])
		if err != nil {
			return nil, fmt.Errorf("%w: sidecar holds an invalid checksum", pverrors.ErrIntegrity)
		}
		if !bytes.Equal(sum[:], want) {
			return nil, fmt.Errorf("%w: shard %d failed checksum after reconstruction", pverrors.ErrUnrecoverable, i)
		}
		copy(padded[i*size:(i+1)*size], shards[i])
	}
	return bytes.Clone(padded[:sc.DataLength]), nil
}
