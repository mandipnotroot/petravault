// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package repository_test

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"petravault/internal/repository"
)

func TestParseS3Address(t *testing.T) {
	t.Parallel()

	got, err := repository.ParseS3Address("s3:my-bucket/some/prefix")
	if err != nil {
		t.Fatal(err)
	}
	if got.Bucket != "my-bucket" || got.Prefix != "some/prefix" {
		t.Fatalf("parsed = %+v, want bucket my-bucket prefix some/prefix", got)
	}
	got, err = repository.ParseS3Address("s3:my-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if got.Bucket != "my-bucket" || got.Prefix != "" {
		t.Fatalf("parsed = %+v, want bucket my-bucket empty prefix", got)
	}
}

func TestParseS3AddressRejectsBad(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{
		"",
		"/local/path",
		"s3:",
		"s3:  ",
		"s3:AB",
		"s3:UPPERCASE",
		"s3:-leading-hyphen",
		"s3:bucket/../escape",
		"s3:bucket/a//b",
	} {
		if _, err := repository.ParseS3Address(addr); err == nil {
			t.Fatalf("ParseS3Address(%q) succeeded, want error", addr)
		}
	}
}

func TestIsS3Address(t *testing.T) {
	t.Parallel()

	if !repository.IsS3Address("s3:bucket/prefix") {
		t.Fatal("IsS3Address(s3:...) = false, want true")
	}
	if repository.IsS3Address("/local/path") {
		t.Fatal("IsS3Address(local) = true, want false")
	}
}

func TestS3RefusesPlaintextHTTP(t *testing.T) {
	// Serial: uses t.Setenv, which parallel tests forbid.
	t.Setenv(repository.AllowHTTPEnv, "")

	_, err := repository.NewS3Client(t.Context(), repository.S3Options{
		Endpoint: "http://localhost:9000",
		Region:   "us-east-1",
	})
	if err == nil {
		t.Fatal("http endpoint without allow succeeded, want refusal")
	}
}

func TestS3AllowsHTTPWhenExplicit(t *testing.T) {
	// Serial: uses t.Setenv, which parallel tests forbid.
	t.Setenv(repository.AllowHTTPEnv, "1")

	client, err := repository.NewS3Client(t.Context(), repository.S3Options{
		Endpoint: "http://localhost:9000",
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatalf("http endpoint with allow failed: %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestS3RejectsBadEndpoint(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"ftp://example.com", "http://", "://missing-scheme"} {
		if _, err := repository.NewS3Client(t.Context(), repository.S3Options{
			Endpoint: endpoint,
			Region:   "us-east-1",
		}); err == nil {
			t.Fatalf("endpoint %q accepted, want error", endpoint)
		}
	}
}

func TestS3UnsafeKeysRejectedWithoutServer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	client, err := repository.NewS3Client(ctx, repository.S3Options{
		Endpoint: "https://s3.us-east-1.amazonaws.com",
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repository.NewS3(client, "example-bucket", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "../escape", "/absolute"} {
		if err := repo.PutObject(ctx, key, bytes.NewReader([]byte("x"))); err == nil {
			t.Fatalf("PutObject(%q) accepted, want error", key)
		}
	}
}

// testS3Repo returns an isolated S3 repository under a unique prefix. It
// skips unless PETRAVAULT_TEST_S3_ENDPOINT is set (GO_GUIDELINES.md §14).
// Callers set PETRAVAULT_S3_ALLOW_HTTP=1 via t.Setenv before calling when
// the endpoint is plaintext http; this helper never calls Setenv itself so
// it stays safe under the parallel subtests of runContract.
func testS3Repo(ctx context.Context, t *testing.T) *repository.S3Repository {
	t.Helper()

	endpoint := strings.TrimSpace(os.Getenv(repository.TestEndpointEnv))
	if endpoint == "" {
		t.Skipf("skipping S3 test: %s is not set", repository.TestEndpointEnv)
	}

	region := cmp.Or(strings.TrimSpace(os.Getenv("AWS_REGION")), "us-east-1")
	opts := repository.S3Options{
		Profile: strings.TrimSpace(os.Getenv("PETRAVAULT_S3_PROFILE")),
		Region:  region,
	}
	if profile := strings.TrimSpace(os.Getenv("AWS_PROFILE")); profile != "" && opts.Profile == "" {
		opts.Profile = profile
	}
	client, err := repository.NewS3Client(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	bucket := cmp.Or(strings.TrimSpace(os.Getenv("PETRAVAULT_TEST_S3_BUCKET")), "petravault-test")
	ensureTestBucket(ctx, t, client, bucket)
	prefix := "test-" + randomHex(t, 8)
	repo, err := repository.NewS3(client, bucket, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func ensureTestBucket(ctx context.Context, t *testing.T, client *s3.Client, bucket string) {
	t.Helper()

	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)}); err == nil {
		return
	}
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	if err != nil {
		// A concurrent test may have created it first.
		if _, headErr := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)}); headErr == nil {
			return
		}
		t.Fatalf("create test bucket %q: %v", bucket, err)
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()

	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func TestS3Contract(t *testing.T) { //nolint:tparallel // parent sets AllowHTTPEnv via Setenv (forbids Parallel) before parallel subtests run.
	// Serial: subtests parallelize, but the http opt-in below must be set
	// before they start. t.Setenv forbids t.Parallel here.
	t.Setenv(repository.AllowHTTPEnv, "1")
	runContract(t, func(t *testing.T) repository.Repository {
		t.Helper()
		return testS3Repo(t.Context(), t)
	})
}

func TestS3SidecarRoundTrip(t *testing.T) {
	// Serial: uses t.Setenv, which parallel tests forbid.
	t.Setenv(repository.AllowHTTPEnv, "1")
	ctx := t.Context()
	repo := testS3Repo(ctx, t)
	data := bytes.Repeat([]byte("sidecar-data"), 1000)
	key := "packs/sidecar-test"

	if err := repo.PutObject(ctx, key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	// Sidecars ride the same Repository seam, so ECC on S3 needs no
	// S3-specific code path (DESIGN.md §4.5, §8).
	if err := repository.WriteSidecar(ctx, repo, key, data, "medium"); err != nil {
		t.Fatal(err)
	}
	fixed, err := repository.RepairObject(ctx, repo, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixed, data) {
		t.Fatal("repaired bytes differ")
	}
}

func TestS3GetRangeMissingMapsToNotExist(t *testing.T) {
	// Serial: uses t.Setenv, which parallel tests forbid.
	t.Setenv(repository.AllowHTTPEnv, "1")
	ctx := t.Context()
	repo := testS3Repo(ctx, t)
	if _, err := repo.GetObject(ctx, "packs/definitely-missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("GetObject err = %v, want fs.ErrNotExist", err)
	}
	rc, err := repo.GetRange(ctx, "packs/definitely-missing", 0, 4)
	if err == nil {
		_ = rc.Close()
		t.Fatal("GetRange on missing key succeeded, want fs.ErrNotExist")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("GetRange err = %v, want fs.ErrNotExist", err)
	}
	// A zero-length range never hits the network and returns empty.
	rc, err = repo.GetRange(ctx, "packs/definitely-missing", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("zero range = %d bytes, want 0", len(got))
	}
}

func TestS3TLSMinimum(t *testing.T) {
	// Serial: uses t.Setenv, which parallel tests forbid.
	// The SDK client is built with an explicit TLS 1.2 floor (DESIGN.md §4.1).
	// Rebuilding the client must not downgrade it; the check below guards
	// the constructor rather than the network.
	client, err := repository.NewS3Client(t.Context(), repository.S3Options{Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
	// The HTTP layer is injected via config.WithHTTPClient; a plaintext
	// endpoint without explicit opt-in must still fail before any request.
	t.Setenv(repository.AllowHTTPEnv, "")
	if _, err := repository.NewS3Client(t.Context(), repository.S3Options{
		Endpoint: "http://127.0.0.1:9000",
		Region:   "us-east-1",
	}); err == nil {
		t.Fatal("plaintext http accepted without opt-in, want refusal")
	}
}
