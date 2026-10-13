// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package repository defines the storage backend seam used by every other
// package (DESIGN.md §8). Implementations share one contract: immutable,
// uniquely named objects; PutObjectIfAbsent as the compare-and-swap behind
// the lock protocol (§10.2); ranged reads so restore fetches one chunk
// without downloading a whole pack.
package repository

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	pverrors "petravault/internal/errors"
)

// S3 address and environment handling (DESIGN.md §8).
const (
	// S3Scheme is the repository address prefix: s3:<bucket>[/<prefix>].
	S3Scheme = "s3:"
	// TestEndpointEnv overrides the S3 endpoint for local S3-compatible
	// test servers. Integration tests set it; production uses AWS
	// endpoints resolved by the SDK (DESIGN.md §8, GO_GUIDELINES.md §14).
	TestEndpointEnv = "PETRAVAULT_TEST_S3_ENDPOINT" //nolint:gosec // environment variable name, not a secret.
	// AllowHTTPEnv explicitly enables plaintext http:// endpoints for
	// local test servers. Anything else refuses http (DESIGN.md §8).
	AllowHTTPEnv = "PETRAVAULT_S3_ALLOW_HTTP" //nolint:gosec // environment variable name, not a secret.
	// AWSEndpointEnv is the SDK-standard endpoint override
	// (AWS_ENDPOINT_URL_S3). It is honored alongside TestEndpointEnv.
	AWSEndpointEnv = "AWS_ENDPOINT_URL_S3"
)

// S3Address is a parsed s3:<bucket>[/<prefix>] repository address.
type S3Address struct {
	// Bucket is the S3 bucket name.
	Bucket string
	// Prefix scopes the repository layout under the bucket. Empty means
	// the layout sits at the bucket root.
	Prefix string
}

// ParseS3Address parses s3:<bucket>[/<prefix>] and fails closed on any
// malformed address (DESIGN.md §8).
func ParseS3Address(s string) (S3Address, error) {
	rest, ok := strings.CutPrefix(s, S3Scheme)
	if !ok {
		return S3Address{}, fmt.Errorf("%w: repository address %q is not an s3 address (want s3:<bucket>[/<prefix>])", pverrors.ErrUsage, s)
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return S3Address{}, fmt.Errorf("%w: s3 repository address is empty (want s3:<bucket>[/<prefix>])", pverrors.ErrUsage)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	bucket = strings.TrimSpace(bucket)
	if !validBucket(bucket) {
		return S3Address{}, fmt.Errorf("%w: invalid s3 bucket %q", pverrors.ErrUsage, bucket)
	}
	prefix = strings.Trim(prefix, "/")
	prefix = strings.TrimSpace(prefix)
	if prefix != "" {
		if err := validPrefix(prefix); err != nil {
			return S3Address{}, err
		}
	}
	return S3Address{Bucket: bucket, Prefix: prefix}, nil
}

// IsS3Address reports whether path is an s3:<bucket>[/<prefix>] address.
func IsS3Address(path string) bool {
	_, ok := strings.CutPrefix(path, S3Scheme)
	return ok
}

// validBucket enforces S3 DNS-compatible bucket names so a typo fails
// fast instead of signing a request AWS will reject.
func validBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 {
		return false
	}
	for _, r := range bucket {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	first, last := bucket[0], bucket[len(bucket)-1]
	if first == '-' || first == '.' || last == '-' || last == '.' {
		return false
	}
	if strings.Contains(bucket, "..") {
		return false
	}
	return true
}

// validPrefix rejects prefixes that could escape the repository scope.
func validPrefix(prefix string) error {
	if prefix == "" || !filepath.IsLocal(prefix) {
		return fmt.Errorf("%w: invalid s3 prefix %q", pverrors.ErrUsage, prefix)
	}
	for segment := range strings.SplitSeq(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%w: invalid s3 prefix %q", pverrors.ErrUsage, prefix)
		}
	}
	return nil
}

// S3Options configures the S3 client. Credentials never appear here; they
// come from the SDK-standard chain (environment, shared config, IAM roles)
// (DESIGN.md §7, §8).
type S3Options struct {
	// Profile selects the AWS named profile (config.S3.Profile).
	Profile string
	// Region selects the AWS region (config.S3.Region). Empty lets the
	// SDK resolve it from the environment or shared config.
	Region string
	// Endpoint overrides the S3 endpoint for S3-compatible stores.
	// Empty resolves from PETRAVAULT_TEST_S3_ENDPOINT, then
	// AWS_ENDPOINT_URL_S3, then the SDK defaults.
	Endpoint string
}

// endpoint resolves the effective S3 endpoint: explicit, then test, then
// AWS-standard env, then none (SDK defaults).
func (o S3Options) endpoint() string {
	if strings.TrimSpace(o.Endpoint) != "" {
		return strings.TrimSpace(o.Endpoint)
	}
	if v := strings.TrimSpace(os.Getenv(TestEndpointEnv)); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(AWSEndpointEnv))
}

// tlsHTTPClient enforces TLS 1.2 minimum (1.3 where the endpoint supports
// it) and bounds every outbound call (DESIGN.md §4.1, §8).
func tlsHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
	cloned := transport.Clone()
	cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 5 * time.Minute, Transport: cloned}
}

// checkEndpointScheme refuses plaintext http:// unless explicitly enabled
// for local test servers, and rejects non-http(s) schemes.
func checkEndpointScheme(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: invalid s3 endpoint %q", pverrors.ErrUsage, endpoint)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		allow := strings.ToLower(strings.TrimSpace(os.Getenv(AllowHTTPEnv)))
		if allow == "1" || allow == "true" || allow == "yes" {
			return nil
		}
		return fmt.Errorf("%w: refusing plaintext http s3 endpoint %q (set %s=1 for local test servers only)", pverrors.ErrUsage, endpoint, AllowHTTPEnv)
	default:
		return fmt.Errorf("%w: invalid s3 endpoint scheme %q (want https)", pverrors.ErrUsage, u.Scheme)
	}
}

// NewS3Client builds the S3 client from S3Options. It uses the SDK-standard
// credential chain and its built-in transient-error retry, so Petravault
// needs no retry layer of its own (DESIGN.md §6, §8).
func NewS3Client(ctx context.Context, opts S3Options) (*s3.Client, error) {
	endpoint := opts.endpoint()
	if err := checkEndpointScheme(endpoint); err != nil {
		return nil, err
	}
	var loadOpts []func(*config.LoadOptions) error
	if strings.TrimSpace(opts.Region) != "" {
		loadOpts = append(loadOpts, config.WithRegion(strings.TrimSpace(opts.Region)))
	}
	if strings.TrimSpace(opts.Profile) != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(strings.TrimSpace(opts.Profile)))
	}
	if endpoint != "" {
		loadOpts = append(loadOpts, config.WithBaseEndpoint(endpoint))
	}
	loadOpts = append(loadOpts, config.WithHTTPClient(tlsHTTPClient()))
	loadOpts = append(loadOpts, config.WithRetryMode(aws.RetryModeStandard))
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		// Custom endpoints (MinIO and other S3-compatible stores)
		// require path-style addressing; AWS uses virtual-hosted.
		o.UsePathStyle = endpoint != ""
		// S3-compatible stores may not implement the newest
		// checksums; only require them when the operation needs one.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return client, nil
}

// S3Repository is a Repository backed by an S3 bucket (and optional prefix).
// The S3 PUT is atomic; an interrupted write never leaves a partial object,
// and no multipart state needs aborting because objects are written with
// single PUTs well under the single-PUT size limit (DESIGN.md §8). The
// client is safe for concurrent use.
type S3Repository struct {
	client *s3.Client
	bucket string
	prefix string
}

// NewS3 validates its inputs and returns the repository. The client must be
// non-nil (see NewS3Client); bucket and prefix follow ParseS3Address rules.
func NewS3(client *s3.Client, bucket, prefix string) (*S3Repository, error) {
	if client == nil {
		return nil, errors.New("open s3 repository: client is nil")
	}
	if !validBucket(bucket) {
		return nil, fmt.Errorf("%w: invalid s3 bucket %q", pverrors.ErrUsage, bucket)
	}
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix != "" {
		if err := validPrefix(prefix); err != nil {
			return nil, err
		}
	}
	return &S3Repository{client: client, bucket: bucket, prefix: prefix}, nil
}

// OpenS3 parses address, builds the client, and verifies the bucket exists.
// A missing bucket is an error, never created implicitly: the operator
// creates it (and enables Versioning/Object Lock) out of band (DESIGN.md §8).
func OpenS3(ctx context.Context, address string, opts S3Options) (*S3Repository, error) {
	parsed, err := ParseS3Address(address)
	if err != nil {
		return nil, err
	}
	client, err := NewS3Client(ctx, opts)
	if err != nil {
		return nil, err
	}
	repo, err := NewS3(client, parsed.Bucket, parsed.Prefix)
	if err != nil {
		return nil, err
	}
	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(parsed.Bucket)}); err != nil {
		return nil, fmt.Errorf("head s3 bucket %q: %w", parsed.Bucket, err)
	}
	return repo, nil
}

// Bucket returns the bucket name.
func (s *S3Repository) Bucket() string {
	return s.bucket
}

// Prefix returns the repository prefix under the bucket (possibly empty).
func (s *S3Repository) Prefix() string {
	return s.prefix
}

// Address returns the canonical s3:<bucket>[/<prefix>] address.
func (s *S3Repository) Address() string {
	if s.prefix == "" {
		return S3Scheme + s.bucket
	}
	return S3Scheme + s.bucket + "/" + s.prefix
}

// fullKey scopes key under the repository prefix. Keys are untrusted input
// when read back from storage, so anything that could escape is rejected.
func (s *S3Repository) fullKey(key string) (string, error) {
	if key == "" || !filepath.IsLocal(key) {
		return "", fmt.Errorf("invalid object key %q", key)
	}
	if s.prefix == "" {
		return key, nil
	}
	return s.prefix + "/" + key, nil
}

// stripPrefix removes the repository prefix from a listed S3 key.
func (s *S3Repository) stripPrefix(full string) string {
	if s.prefix == "" {
		return full
	}
	stripped, _ := strings.CutPrefix(full, s.prefix+"/")
	return stripped
}

// PutObject implements Repository with a single atomic S3 PUT. Objects are
// packs (~16 MiB), indexes, snapshots, slots, and configs: all far below
// the single-PUT limit, so no multipart upload is needed.
func (s *S3Repository) PutObject(ctx context.Context, key string, r io.Reader) error {
	full, err := s.fullKey(key)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(full),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	}); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// PutObjectIfAbsent implements Repository with the conditional-write
// compare-and-swap: If-None-Match "*" succeeds only when the key does not
// exist. A lost race returns (false, nil), never an overwrite (DESIGN.md
// §10.2). Stores without conditional-write support fail closed with the
// underlying error.
func (s *S3Repository) PutObjectIfAbsent(ctx context.Context, key string, r io.Reader) (bool, error) {
	full, err := s.fullKey(key)
	if err != nil {
		return false, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", key, err)
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(full),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		IfNoneMatch:   aws.String("*"),
	})
	if err == nil {
		return true, nil
	}
	if isPreconditionFailed(err) {
		return false, nil
	}
	return false, fmt.Errorf("put-if-absent %s: %w", key, err)
}

// GetObject implements Repository. A missing key returns an error wrapping
// fs.ErrNotExist.
func (s *S3Repository) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	full, err := s.fullKey(key)
	if err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(full),
	})
	if err != nil {
		if isNotFoundKey(err) {
			return nil, fmt.Errorf("get %s: %w: %w", key, fs.ErrNotExist, err)
		}
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	return out.Body, nil
}

// GetRange implements Repository with one S3 ranged GET, so a single chunk
// is fetched without downloading its whole pack.
func (s *S3Repository) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 || length < 0 {
		return nil, fmt.Errorf("invalid range offset=%d length=%d for %s", offset, length, key)
	}
	if length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	full, err := s.fullKey(key)
	if err != nil {
		return nil, err
	}
	// S3 ranges are inclusive: bytes=start-end.
	end := offset + length - 1
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(full),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", offset, end)),
	})
	if err != nil {
		if isNotFoundKey(err) {
			return nil, fmt.Errorf("get range %s: %w: %w", key, fs.ErrNotExist, err)
		}
		return nil, fmt.Errorf("get range %s: %w", key, err)
	}
	return out.Body, nil
}

// DeleteObject implements Repository. Deleting a missing key is not an
// error: S3 deletes are idempotent.
func (s *S3Repository) DeleteObject(ctx context.Context, key string) error {
	full, err := s.fullKey(key)
	if err != nil {
		return err
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(full),
	}); err != nil {
		return fmt.Errorf("delete %s: %w", key, err)
	}
	return nil
}

// Exists implements Repository with HeadObject.
func (s *S3Repository) Exists(ctx context.Context, key string) (bool, error) {
	full, err := s.fullKey(key)
	if err != nil {
		return false, err
	}
	if _, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(full),
	}); err != nil {
		if isNotFoundKey(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", key, err)
	}
	return true, nil
}

// List implements Repository. Names use "/" separators and are sorted.
func (s *S3Repository) List(ctx context.Context, prefix string) ([]string, error) {
	s3Prefix := prefix
	if s.prefix != "" {
		if prefix == "" {
			s3Prefix = s.prefix
		} else {
			s3Prefix = s.prefix + "/" + prefix
		}
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s3Prefix),
	})
	var out []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			stripped := s.stripPrefix(*obj.Key)
			// The bucket prefix itself never appears as an object, but
			// S3-compatible stores may return it; skip empties.
			if stripped == "" {
				continue
			}
			out = append(out, stripped)
		}
	}
	return slices.Sorted(slices.Values(out)), nil
}

// isNotFoundKey reports whether err means the object key is missing. A
// missing bucket is not a missing key: it fails closed as an error.
func isNotFoundKey(err error) bool {
	if _, ok := errors.AsType[*types.NoSuchKey](err); ok {
		return true
	}
	if _, ok := errors.AsType[*types.NotFound](err); ok {
		return true
	}
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchKey":
			return true
		}
	}
	return false
}

// isPreconditionFailed reports whether err is the conditional-write loss:
// another writer created the key first (412 Precondition Failed, or 409
// ConditionalRequestConflict on concurrent writes).
func isPreconditionFailed(err error) bool {
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		switch apiErr.ErrorCode() {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return true
		}
	}
	return false
}

// Open returns the repository for path: an S3 repository for
// s3:<bucket>[/<prefix>] addresses, a local one otherwise. S3 credentials
// come from the SDK-standard chain; profile and region come from opts.
func Open(ctx context.Context, path string, s3opts S3Options) (Repository, error) {
	if IsS3Address(path) {
		return OpenS3(ctx, path, s3opts)
	}
	return NewLocal(path), nil
}
