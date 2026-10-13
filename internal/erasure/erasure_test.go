// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package erasure_test

import (
	"bytes"
	"errors"
	"testing"

	"petravault/internal/erasure"
	pverrors "petravault/internal/errors"
)

func TestParseProfiles(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		in   string
		k, m int
		eff  string
	}{
		{in: "low", k: 50, m: 1, eff: "2.0%"},
		{in: "medium", k: 20, m: 1, eff: "5.0%"},
		{in: "high", k: 20, m: 3, eff: "15.0%"},
		{in: "7%", k: 14, m: 1, eff: "7.1%"},
		{in: "25%", k: 20, m: 5, eff: "25.0%"},
		{in: "2%", k: 50, m: 1, eff: "2.0%"},
		{in: "100%", k: 20, m: 20, eff: "100.0%"},
	} {
		p, err := erasure.Parse(tt.in)
		if err != nil {
			t.Fatalf("Parse(%q) failed: %v", tt.in, err)
		}
		if p.K != tt.k || p.M != tt.m {
			t.Fatalf("Parse(%q) = k=%d m=%d, want k=%d m=%d", tt.in, p.K, p.M, tt.k, tt.m)
		}
		if p.Effective() != tt.eff {
			t.Fatalf("Parse(%q) effective = %q, want %q", tt.in, p.Effective(), tt.eff)
		}
		if p.Off {
			t.Fatalf("Parse(%q) is off, want enabled", tt.in)
		}
	}
	off, err := erasure.Parse("off")
	if err != nil {
		t.Fatal(err)
	}
	if !off.Off || off.Effective() != "off" {
		t.Fatalf("off = %+v, want disabled", off)
	}
}

func TestParseRejectsOutOfRange(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "bogus", "ultra", "%", "5", "0%", "0.4%", "0.1%", "101%", "200%", "7.555%", "a%", "--ecc", "OFFx"} {
		if _, err := erasure.Parse(bad); err == nil {
			t.Fatalf("Parse(%q) accepted, want rejection", bad)
		} else if !errors.Is(err, pverrors.ErrUsage) {
			t.Fatalf("Parse(%q) error = %v, want usage error", bad, err)
		}
	}
}

func TestEffectiveCoversRequested(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"low", "medium", "high", "0.5%", "2%", "5%", "7%", "8%", "15%", "25%", "100%"} {
		p, err := erasure.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if p.K+p.M > erasure.MaxShards {
			t.Fatalf("%s exceeds the shard limit", in)
		}
		// Effective m/k must cover the requested overhead: m*10000 >= bps*k.
		if p.M*10000 < p.OverheadBPS*p.K {
			t.Fatalf("%s effective %s does not cover the request", in, p.Effective())
		}
	}
}

func damageShards(t *testing.T, data []byte, k int, indices ...int) []byte {
	t.Helper()
	size := erasure.ShardSize(len(data), k)
	out := bytes.Clone(data)
	for _, i := range indices {
		pos := i*size + size/2
		if pos >= len(out) {
			pos = i * size
		}
		out[pos] ^= 0x01
	}
	return out
}

func TestEncodeRepairRoundTrip(t *testing.T) {
	t.Parallel()

	p, err := erasure.Parse("medium")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte((i*31 + 7) & 0xff)
	}
	sidecar, err := erasure.Encode(data, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := erasure.Verify(data, sidecar); err != nil {
		t.Fatalf("intact verify failed: %v", err)
	}
	// One damaged shard (the budget) repairs.
	damaged := damageShards(t, data, p.K, 3)
	if err := erasure.Verify(damaged, sidecar); err == nil {
		t.Fatal("verify accepted damage, want failure")
	} else if !errors.Is(err, pverrors.ErrIntegrity) {
		t.Fatalf("verify error = %v, want integrity failure", err)
	}
	fixed, err := erasure.Repair(damaged, sidecar)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if !bytes.Equal(fixed, data) {
		t.Fatal("repair did not restore the original bytes")
	}
	if err := erasure.Verify(fixed, sidecar); err != nil {
		t.Fatalf("repaired verify failed: %v", err)
	}
	// Two damaged shards exceed the single-shard budget.
	damaged2 := damageShards(t, data, p.K, 1, 2)
	if _, err := erasure.Repair(damaged2, sidecar); err == nil {
		t.Fatal("repair accepted damage beyond the budget, want failure")
	} else if !errors.Is(err, pverrors.ErrUnrecoverable) {
		t.Fatalf("repair error = %v, want unrecoverable", err)
	}
}

func TestHighRepairsThreeShards(t *testing.T) {
	t.Parallel()

	p, err := erasure.Parse("high")
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 100000)
	sidecar, err := erasure.Encode(data, p)
	if err != nil {
		t.Fatal(err)
	}
	damaged := damageShards(t, data, p.K, 0, 5, 19)
	fixed, err := erasure.Repair(damaged, sidecar)
	if err != nil {
		t.Fatalf("high repair failed: %v", err)
	}
	if !bytes.Equal(fixed, data) {
		t.Fatal("high repair mismatch")
	}
	damaged4 := damageShards(t, data, p.K, 0, 1, 2, 3)
	if _, err := erasure.Repair(damaged4, sidecar); err == nil {
		t.Fatal("repair accepted four damaged shards under high, want failure")
	} else if !errors.Is(err, pverrors.ErrUnrecoverable) {
		t.Fatalf("error = %v, want unrecoverable", err)
	}
}

func TestSmallObject(t *testing.T) {
	t.Parallel()

	p, err := erasure.Parse("low")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("tiny object, smaller than k")
	sidecar, err := erasure.Encode(data, p)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := erasure.Repair(bytes.Clone(data), sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixed, data) {
		t.Fatal("small object mismatch")
	}
}

func TestEncodeOffRefused(t *testing.T) {
	t.Parallel()

	off, err := erasure.Parse("off")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := erasure.Encode([]byte("data"), off); err == nil {
		t.Fatal("Encode accepted off, want refusal")
	}
	if _, err := erasure.Encode(nil, erasure.Default()); err == nil {
		t.Fatal("Encode accepted empty input, want refusal")
	}
}

func TestSidecarRejectsTampering(t *testing.T) {
	t.Parallel()

	p := erasure.Default()
	data := bytes.Repeat([]byte("sidecar tamper target"), 4000)
	sidecar, err := erasure.Encode(data, p)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(sidecar)
	bad[len(bad)-10] ^= 0x01
	if err := erasure.Verify(data, bad); err == nil {
		t.Fatal("Verify accepted a tampered sidecar")
	}
	// Repair of intact data tolerates parity-only sidecar damage: data
	// checksums still match, so reads succeed while Verify reports it.
	// A truncated sidecar is unusable for either path.
	truncated := sidecar[:len(sidecar)/2]
	if err := erasure.Verify(data, truncated); err == nil {
		t.Fatal("Verify accepted a truncated sidecar")
	}
	if _, err := erasure.Repair(data, truncated); err == nil {
		t.Fatal("Repair accepted a truncated sidecar")
	}
	if _, err := erasure.Decode([]byte(`{"unknown":true}`)); err == nil {
		t.Fatal("Decode accepted unknown fields")
	}
}

func TestSidecarKey(t *testing.T) {
	t.Parallel()

	if got := erasure.SidecarKey("packs/abc"); got != "packs/abc.ecc" {
		t.Fatalf("SidecarKey = %q", got)
	}
}

func FuzzDecodeNoPanic(f *testing.F) {
	p := erasure.Default()
	sidecar, err := erasure.Encode(bytes.Repeat([]byte("seed"), 100), p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sidecar)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = erasure.Decode(data)
	})
}
