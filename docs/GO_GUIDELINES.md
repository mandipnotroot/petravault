<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Go Coding Guide

How to write the Go code for Petravault. This guide sits next to
[DESIGN.md](DESIGN.md) and [COMMIT_GUIDE.md](COMMIT_GUIDE.md) and **does not repeat them**.
It says how to turn what they specify into Go.

If you are not sure what the system should do, read `DESIGN.md`. If you are not sure how to
write a commit, read `COMMIT_GUIDE.md`. If you are not sure how to write the Go, read this.

> If `DESIGN.md` and this guide disagree about **behavior**, `DESIGN.md` wins.
> If a code change alters behavior, update `DESIGN.md` in the same pull request.

---

## 1. Where the Rules Live

| Topic | Authority |
|---|---|
| Architecture, data and metadata pipelines | DESIGN.md §2 |
| Chunking, keyed IDs, determinism, fast path | DESIGN.md §3 |
| Crypto primitives, key hierarchy, associated data, key slots, signatures, erasure coding | DESIGN.md §4 |
| Identity, trust list, revocation | DESIGN.md §5 |
| Allowed and forbidden libraries, licensing | DESIGN.md §6 |
| Configuration formats, precedence, secret handling | DESIGN.md §7 |
| `Repository` interface and on-disk/S3 layout | DESIGN.md §8 |
| Snapshots, verification, restore safety, atomic commit | DESIGN.md §9 |
| Concurrency and the lock protocol | DESIGN.md §10 |
| Scheduler, unattended unlock, retention | DESIGN.md §11 |
| Threat model | DESIGN.md §12 |
| Testing strategy and the attack-simulation table | DESIGN.md §13 |
| Package structure | DESIGN.md §14 |
| CLI commands and exit codes | DESIGN.md §16 |
| Definition of done | DESIGN.md §17 |
| Commit messages (Conventional Commits), scopes, commit size, no tool attribution | COMMIT_GUIDE.md |
| Modern Go language and standard-library idioms | JetBrains Modern Go Guidelines (section 3) |
| Everything about Go style, tooling, and CI | this guide |

---

## 2. Golden Rules

1. **Never hand-roll a cryptographic primitive** (DESIGN.md §6). Compose the approved libraries only.
2. **Dependencies are limited to DESIGN.md §6.** A new one needs a written reason, a license check, and a reviewed PR (section 15).
3. **Every file carries a REUSE header (`SPDX-FileCopyrightText:` + `SPDX-License-Identifier: GPL-3.0-only`)** ([REUSE](https://reuse.software/), DESIGN.md §6).
4. **Fail closed.** Unknown config keys are rejected, unverified data is never used, damage beyond the parity budget is reported, never ignored (DESIGN.md §4.5, §7).
5. **Verify before you use.** Signature, then trust, then history, then chunks, then write (DESIGN.md §9).
6. **No secrets in logs, arguments, config files, or error messages** (DESIGN.md §7, §11.2).
7. **Everything that is hashed, signed, or named by its hash is built from deterministic bytes** (section 8).
8. **Everything passes `make check`** before a PR is opened.
9. **Commits follow [COMMIT_GUIDE.md](COMMIT_GUIDE.md)**, including its no-tool-attribution rule.

---

## 3. Modern Go Idioms (JetBrains Guidelines)

Repository: https://github.com/JetBrains/go-modern-guidelines

Language and standard-library idioms are **not** listed in this guide. They come from the JetBrains
Modern Go Guidelines, which cover features from Go 1.0 through Go 1.27 (this project targets Go 1.27+),
including everything the `modernize` analyzer targets. The guidelines read the Go version from
`go.mod` and only suggest features available up to that version.

Examples of what they enforce: `slices.Contains` over search loops, `min`/`max` over if-else,
`for i := range n`, `any` over `interface{}`, `errors.Is`/`errors.As`, `cmp.Or`,
`strings.CutPrefix`, `sync.WaitGroup.Go`, `omitzero`, `t.Context()`, `b.Loop()`, and newer additions
such as `new(value)` and `errors.AsType[T]`. The full catalogue with before/after examples is
[`FEATURES.md`](https://github.com/JetBrains/go-modern-guidelines/blob/main/FEATURES.md) in their repository.

### 3.1 Requirements

- Go toolchain on `PATH`. The CLI installs itself on first use with `go install` into a local cache and never modifies the project.
- It targets Go 1.27+ (required for `crypto/hpke` and `crypto/mldsa` in the standard library, DESIGN.md §6).

### 3.2 Install

| Agent / tool | Install |
|---|---|
| Claude Code | `/plugin marketplace add JetBrains/go-modern-guidelines` then `/plugin install modern-go-guidelines@goland-claude-marketplace` |
| Junie | `/extensions marketplace add JetBrains/go-modern-guidelines` then `/extensions install modern-go-guidelines` |
| Codex | `codex plugin marketplace add JetBrains/go-modern-guidelines` then `codex plugin add modern-go-guidelines@goland-codex-marketplace` |
| Cursor | `cursor-agent plugin marketplace add https://github.com/JetBrains/go-modern-guidelines`, then install with `/plugins` |
| Others (OpenCode, etc.) | `npx skills add JetBrains/go-modern-guidelines` |

Explicit invocation in Claude Code: `/modern-go-guidelines:use-modern-go`.

### 3.3 Required workflow

1. Before editing a Go file, run the skill's `list` subcommand for that file:
   `sh "<skill-dir>/scripts/run-tool.sh" list --file-path path/to/file.go`
2. Read the **complete** output. Do not pipe it through `head`, `tail`, `grep`, or `sed`; older guidelines still apply.
3. Treat the returned guidelines as authoritative, even when nearby code uses an older pattern.
4. Skip one only if it would not compile, would change behavior, or clearly does not fit. Before skipping one that looks relevant, run `explain <guideline-id>`.
5. Use `explain <id> [<id>...]` for details. Never call `explain` without IDs.

### 3.4 Updating existing code

```bash
go fix ./...    # Go 1.26+: runs the modernizers
go run golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest -fix -test ./...
```

Review the diff, run the tests, and commit modernization **separately** from feature work
(`refactor:` or `style:` per COMMIT_GUIDE.md).

### 3.5 Enforcement

The guidelines help while writing; linters enforce in CI. The `modernize`, `intrange`, `copyloopvar`,
`usetesting`, and `perfsprint` linters in section 6 catch most regressions.

---

## 4. Go Version, Module, File Headers

```go
module petravault

go 1.27
```

- `go.mod` is the source of truth for the language version. DESIGN.md targets Go 1.27+ because `crypto/mldsa` (1.27) and `crypto/hpke` (1.26) are standard library. Keep whatever `go mod init`/`go mod tidy` produce (including the exact patch version and any `toolchain` line); never hand-edit the version down.
- The module path is intentionally hosting-independent (`petravault`, not `github.com/<org>/petravault`), so imports are `petravault/internal/<pkg>`. Do not change it to a hosting-qualified path without a breaking-change decision. Use the same `petravault` prefix in `.golangci.yml`.
- Every file (including tests and generated files you check in) starts with a REUSE-compliant header ([REUSE](https://reuse.software/), DESIGN.md §6), then a blank line, so the header is not mistaken for the package doc comment:

```go
// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

// Package chunking splits files into content-defined chunks (DESIGN.md §3).
package chunking
```

- Use `Petravault Contributors` as the holder for new files; when you change a file with a new copyright holder, add your own `SPDX-FileCopyrightText:` line and never remove existing ones. License texts live in `LICENSES/` (e.g. `LICENSES/GPL-3.0-only.txt`).

CI fails on a missing or non-compliant header (`reuse lint`, section 6.4).

---

## 5. Project Structure and Layering

The directory tree is in DESIGN.md §14. Rules for working inside it:

- Everything is under `internal/`. Nothing is public API until DESIGN.md says so.
- `cmd/petravault/main.go` only wires dependencies and calls `run`. No business logic.
- The cross-package attack-simulation suite lives in `tests/attack/` (DESIGN.md §13, §14); unit tests sit next to the code they cover. The `Repository` contract suite lives in `internal/repository` and runs against both backends (S3 is skipped unless `PETRAVAULT_TEST_S3_ENDPOINT` is set).
- No import cycles. Keep the layering one-directional:

| Layer | Packages | May import |
|---|---|---|
| Leaf | `crypto`, `compression`, `chunking`, `erasure`, `config` | the standard library and approved dependencies only |
| Domain | `identity`, `manifest`, `repository`, `pack` | leaf packages |
| Orchestration | `backup`, `restore`, `verify`, `scheduler` | leaf and domain packages (`scheduler` reuses `backup`, DESIGN.md §11) |
| Wiring | `cmd/petravault` | everything |

- Define interfaces at the consumer side and keep them small. `Repository` (DESIGN.md §8), `Chunker` (§3.1), and `Signer` (§6) are the main seams; implementations are chosen in `cmd`.
- No package-level mutable state and no `init()`. Pass dependencies explicitly.
- No packages named `util`, `common`, `helpers`, or `base`.

```go
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(ExitCode(err)) // exit codes: DESIGN.md §16
}
```

(`stop()` is called explicitly before `os.Exit` instead of `defer stop()`,
which would never run and trips the `exitAfterDefer` check.)

---

## 6. Tooling and CI

| Purpose | Tool | Command |
|---|---|---|
| Format | gofumpt + goimports | `go tool golangci-lint fmt` |
| Static analysis | go vet | `go vet ./...` |
| Lint | golangci-lint v2 | `go tool golangci-lint run` |
| Modernize | go fix / modernize | `go fix ./...` |
| Tests | go test | `go test -race -shuffle=on ./...` |
| Vulnerabilities | govulncheck | `go tool govulncheck ./...` |
| Modules | go mod | `go mod tidy && go mod verify` |
| Licenses | license scanner | `make license` |
| REUSE compliance | reuse | `make reuse` |

These match the CI list in DESIGN.md §13 (formatting via `golangci-lint fmt`, `go vet`,
`golangci-lint run`, `go test`, `go test -race`, `go build`, `go mod verify`, `govulncheck`,
dependency scanning, license check, REUSE check).

### 6.1 Pin dev tools in `go.mod` (`tool` directive)

```bash
go get -tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go get -tool golang.org/x/vuln/cmd/govulncheck@latest
```

### 6.2 `.golangci.yml`

```yaml
version: "2"

run:
  timeout: 5m
  tests: true

linters:
  default: standard        # errcheck, govet, ineffassign, staticcheck, unused
  enable:
    - bodyclose
    - contextcheck
    - copyloopvar
    - depguard             # enforces the forbidden-library list (DESIGN.md §6)
    - errname
    - errorlint
    - exhaustive
    - fatcontext
    - forbidigo
    - forcetypeassert
    - gocritic
    - gosec
    - intrange
    - misspell
    - modernize            # remove if your golangci-lint version lacks it
    - nilerr
    - noctx
    - perfsprint
    - prealloc
    - revive
    - sloglint
    - thelper
    - tparallel
    - unconvert
    - usestdlibvars
    - usetesting
    - wastedassign
    - whitespace
  settings:
    depguard:
      rules:
        petravault:
          files:
            - $all
          deny:
            - pkg: gopkg.in/yaml.v3
              desc: archived; use go.yaml.in/yaml/v3 (DESIGN.md §6)
            - pkg: github.com/spf13/viper
              desc: no config-merging framework (DESIGN.md §7)
            - pkg: lukechampine.com/blake3
              desc: one BLAKE3 implementation only, github.com/zeebo/blake3 (DESIGN.md §6)
    errcheck:
      check-type-assertions: true
    forbidigo:
      forbid:
        - pattern: ^log\.(Print|Fatal|Panic).*$
          msg: use log/slog
        - pattern: ^fmt\.Print(f|ln)?$
          msg: write to an injected io.Writer (cmd.OutOrStdout())
        - pattern: ^os\.Exit$
          msg: only cmd/petravault/main.go may exit the process
    gosec:
      excludes:
        - G304             # a backup tool opens caller-supplied paths by design;
                           # paths from manifests go through os.Root (section 11)
    govet:
      enable-all: true
      disable:
        - fieldalignment
        - shadow
    revive:
      rules:
        - name: exported
        - name: package-comments
        - name: error-return
        - name: error-naming
        - name: error-strings
        - name: context-as-argument
        - name: context-keys-type
        - name: var-naming
        - name: unused-parameter
    sloglint:
      no-mixed-args: true
      attr-only: true
      context: scope
  exclusions:
    presets:
      - comments
      - std-error-handling
    rules:
      - path: _test\.go
        linters:
          - gosec
          - errcheck
          - forbidigo
      - path: cmd/petravault/main\.go
        linters:
          - forbidigo

formatters:
  enable:
    - gofumpt
    - goimports
  settings:
    goimports:
      local-prefixes:
        - petravault

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
```

Validate the file after editing it: `go tool golangci-lint config verify`.

### 6.3 `Makefile`

```makefile
.PHONY: fmt vet lint test test-integration fuzz cover vuln license reuse tidy fix build check

TESTFLAGS := -race -shuffle=on -count=1

fmt:
	go tool golangci-lint fmt

vet:
	go vet ./...

lint:
	go tool golangci-lint run

test:
	go test $(TESTFLAGS) ./...

# Needs a local S3-compatible server, see section 14
test-integration:
	go test $(TESTFLAGS) -tags=integration ./...

fuzz:
	go test -run='^$$' -fuzz=FuzzChunker -fuzztime=30s ./internal/chunking

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vuln:
	go tool govulncheck ./...

# Only permissive, GPL-3.0-compatible licenses (DESIGN.md §6).
# go-licenses is one option; use whichever scanner the project standardizes on.
license:
	go run github.com/google/go-licenses@latest check ./... \
		--allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0

reuse:
	reuse lint

tidy:
	go mod tidy
	go mod verify

fix:
	go fix ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$$(git describe --tags --always --dirty)" -o bin/petravault ./cmd/petravault

# Run before every PR
check: fmt vet lint test build vuln license reuse
```

### 6.4 REUSE compliance

The project follows [REUSE](https://reuse.software/): `LICENSES/` holds the license texts,
every file carries `SPDX-FileCopyrightText:` + `SPDX-License-Identifier:` headers (§4),
and uncommentable files (if any) are covered via `.reuse/dep5`.

```bash
pipx install reuse   # or: pip install reuse
reuse lint                # via make: make reuse
```

`reuse lint` replaces any ad hoc header grep: it checks every tracked file, not just `.go` files.

### 6.5 CI (`.github/workflows/ci.yml`)

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - name: Install REUSE tool
        run: pipx install reuse
      - name: Formatting
        run: go tool golangci-lint fmt --diff ./...
      - name: Modules are tidy
        run: |
          go mod tidy
          git diff --exit-code go.mod go.sum
      - run: go mod verify
      - run: go vet ./...
      - run: go tool golangci-lint run
      - run: go build ./...
      - run: go test -race -shuffle=on -count=1 ./...
      - name: Fuzz chunker briefly
        run: go test -run='^$' -fuzz=FuzzChunker -fuzztime=30s ./internal/chunking
      - run: go tool govulncheck ./...
      - run: make license
      - run: make reuse

  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
```

Add the pull-request-title check from [COMMIT_GUIDE.md](COMMIT_GUIDE.md#enforcement-optional) as its own workflow. Integration tests that need an S3-compatible server run in a separate job with that server as a service container.

### 6.6 Editor

- Format on save with `gofumpt`, organize imports with `goimports`.
- Keep `gopls` analyses (including `modernize`) enabled.
- Add a file template that inserts the REUSE header (§4).

---

## 7. Cryptography Coding Rules

The design is in DESIGN.md §4 and the library list in §6. Rules for the Go code in `internal/crypto`
and anything that calls it:

- **Approved libraries only**, wrapped behind small interfaces (`Signer`, `Chunker`, `Repository`) so a component can be swapped (DESIGN.md §6, "algorithm agility").
- **Randomness is `crypto/rand` only**: nonces, salts, key material. Never `math/rand` for anything security-relevant.
- **Fresh random 192-bit nonce for every AEAD object**, stored with the ciphertext. Associated data always binds what DESIGN.md §4.1 lists (`repository_id`, `format_version`, `algorithm_id`, object type, plus `chunk_id` or `snapshot_id` when known).
- **Open failures return a generic error and no plaintext.** Never return partial plaintext on authentication failure.
- **Constant-time comparison** (`crypto/subtle.ConstantTimeCompare`, `hmac.Equal`) for anything secret-derived.
- **Domain separation by constant.** Signature contexts (DESIGN.md §4.3) and `derive_key` contexts (§4.1) are named constants in one place. A signature made for one purpose can never verify for another.
- **Secrets are a dedicated type** that redacts itself and can be zeroed (best effort in Go, DESIGN.md §4.4).
- **Known-answer tests** pin BLAKE3 (plain, keyed, `derive_key`) and the X-Wing key-slot vectors in CI (DESIGN.md §13).
- Argon2id parameters are stored beside the keystore and default to the current OWASP recommendation (DESIGN.md §4.4). Never hard-code them at call sites.

```go
// Signature and derive_key contexts (DESIGN.md §4.1, §4.3).
const (
	ContextManifest   = "petravault manifest v1"
	ContextSlotGrant  = "petravault slot-grant v1"
	ContextRepoConfig = "petravault repo-config v1"
	ContextRevocation = "petravault revocation v1"
)

// Seal encrypts plaintext with a fresh random 192-bit nonce and returns
// nonce || ciphertext || tag. ad must bind the fields listed in DESIGN.md §4.1.
func Seal(key, plaintext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize()) // 24 bytes
	if _, err := rand.Read(nonce); err != nil { // crypto/rand
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

// Open reverses Seal. Any failure returns ErrAuthFailed and no plaintext.
func Open(key, sealed, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrAuthFailed
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}
```

```go
// SecretKey never prints itself and can be zeroed when no longer needed.
type SecretKey struct{ b [32]byte }

func (k *SecretKey) Zero()             { clear(k.b[:]) }
func (SecretKey) String() string       { return "[redacted]" }
func (SecretKey) GoString() string     { return "[redacted]" }
func (SecretKey) LogValue() slog.Value { return slog.StringValue("[redacted]") }
```

---

## 8. Determinism

Anything that is hashed, signed, or named by its hash must come from deterministic bytes, or
dedup, signatures, and golden tests break silently (DESIGN.md §3.3, §9).

- **Sign and verify the stored bytes.** Keep the payload as `[]byte`, verify the signature over it, then unmarshal. Never re-serialize before verifying (DESIGN.md §9).
- **No map iteration order** in anything that is hashed or signed. Build sorted slices (`slices.Sorted(maps.Keys(m))`). The manifest `files` list is ordered by path.
- **Integer math for ECC parameters.** Derive `k` and `m` from basis points (5% = 500), never floats (DESIGN.md §4.5).
- **Chunk boundaries are frozen per repository.** A library upgrade that moves a cut point fails the golden tests until the algorithm ID is deliberately bumped (DESIGN.md §3.3).
- **Times in UTC, RFC 3339** in manifests. Compare file timestamps at full nanosecond precision (DESIGN.md §3.4).
- **No `time.Now()` or randomness hidden inside deterministic functions.** Pass a clock or a reader in.

---

## 9. Errors and Exit Codes

Exit codes are defined in DESIGN.md §16: `0` success, `1` error, `2` usage, `3` completed with
warnings, `4` integrity or trust failure.

- Return errors; reserve `panic` for programmer errors.
- Wrap with context using `%w`. Messages are lowercase with no trailing punctuation.
- **Handle an error once**: return it or log it, never both.
- **Integrity failures wrap `ErrIntegrity`** so the CLI maps them to exit code `4`. They are never downgraded to warnings and never swallowed.
- Never ignore an error. If it is deliberate: `_ = f() // reason`.

```go
const (
	ExitOK        = 0
	ExitError     = 1
	ExitUsage     = 2
	ExitWarnings  = 3
	ExitIntegrity = 4
)

var (
	ErrUsage     = errors.New("usage error")
	ErrWarnings  = errors.New("completed with warnings")
	ErrIntegrity = errors.New("integrity or trust failure")

	// Specific integrity failures wrap ErrIntegrity (exit code 4).
	ErrAuthFailed      = fmt.Errorf("%w: authentication failed", ErrIntegrity)
	ErrBadSignature    = fmt.Errorf("%w: invalid signature", ErrIntegrity)
	ErrUntrustedSigner = fmt.Errorf("%w: signer is not in the trust list", ErrIntegrity)
	ErrRollback        = fmt.Errorf("%w: rollback detected", ErrIntegrity)
	ErrUnrecoverable   = fmt.Errorf("%w: damage exceeds the parity budget", ErrIntegrity)
)

// ExitCode maps an error to the process exit code. Integrity wins over warnings.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrIntegrity):
		return ExitIntegrity
	case errors.Is(err, ErrUsage):
		return ExitUsage
	case errors.Is(err, ErrWarnings):
		return ExitWarnings
	default:
		return ExitError
	}
}
```

Map domain errors to CLI behavior at the boundary only. Inner packages return sentinel or typed errors
and know nothing about exit codes.

---

## 10. Context, Concurrency, Locks

The lock protocol and its ordering rules are DESIGN.md §10.2. Rules for the Go code:

- `ctx context.Context` is the first parameter, named `ctx`. Never store it in a struct. Every `Repository` method takes one.
- Every goroutine has an owner and a stop condition. No fire-and-forget.
- Use `errgroup` with `SetLimit(n)` for bounded fan-out. `n` comes from the `concurrency` setting (DESIGN.md §7).
- Lock objects are created with `PutObjectIfAbsent`; creation is the compare-and-swap. Lock heartbeats run in a goroutine owned by the lock and stopped before the lock is released.
- **Ordering matters and has tests.** A backup writes its marker, then checks for `gc.lock`, then reads indexes. Prune writes `gc.lock`, then lists markers. Do not reorder these steps (DESIGN.md §10.2).
- The same source running two backups of itself is stopped by a local advisory lock on the machine (DESIGN.md §10.2). Wrap the OS call (`flock` on Unix) behind a small build-tagged helper.
- A job that is still running is not started again (DESIGN.md §11.1).
- Always run tests with `-race`.
- Set a timeout on every outbound call. Avoid `time.After` in loops; use a `time.Timer` and stop it.

```go
// Local PutObjectIfAbsent: O_EXCL is the compare-and-swap (DESIGN.md §8, §10.2).
f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
if errors.Is(err, fs.ErrExist) {
	return false, nil // someone else holds it
}
if err != nil {
	return false, fmt.Errorf("create %s: %w", key, err)
}
```

```go
func (l *Lock) heartbeat(ctx context.Context) {
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.refresh(ctx); err != nil {
				l.log.WarnContext(ctx, "lock refresh failed", slog.Any("error", err))
			}
		}
	}
}
```

---

## 11. Files and Restore Safety

The behavior is DESIGN.md §8 (durable writes) and §9 (restore safety). In Go:

- **Durable write**: temp file in the same directory, `Sync`, `Close`, `Rename`, then `Sync` the directory.
- **A verified manifest is still untrusted input to the filesystem.** Reject paths that are not `filepath.IsLocal`, and use `os.Root` so a `..` or a symlink can never leave the destination, including symlinks created earlier in the same restore.
- **Cap decompression** at the repository's maximum chunk size.
- Files holding secrets or job definitions are `0600` and their permissions are checked at load (DESIGN.md §11.2, §12).
- Do not restore setuid/setgid bits. Restore ownership only when running as root (DESIGN.md §9).

```go
func writeDurable(dir, name string, r io.Reader) (err error) {
	tmp, err := os.CreateTemp(dir, name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, r); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
```

```go
root, err := os.OpenRoot(dest)
if err != nil {
	return fmt.Errorf("open destination: %w", err)
}
defer root.Close()

for _, e := range m.Files {
	// Manifest entries are untrusted even after the signature verifies.
	if !filepath.IsLocal(e.Path) {
		return fmt.Errorf("%w: %q", ErrUnsafePath, e.Path)
	}
	// os.Root refuses ".." escapes and symlinks that leave dest.
	f, err := root.OpenFile(e.Path+".petravault-tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", e.Path, err)
	}
	// write chunks (AEAD + BLAKE3 verified first), close, then rename into place
	// and honor --overwrite (DESIGN.md §9)
	_ = f.Close()
}
```

```go
// Cap decompression at the repository's maximum chunk size (DESIGN.md §9).
out, err := io.ReadAll(io.LimitReader(dec, maxChunk+1))
if err != nil {
	return nil, fmt.Errorf("decompress chunk: %w", err)
}
if int64(len(out)) > maxChunk {
	return nil, ErrChunkTooLarge
}
```

---

## 12. Configuration, Secrets, Logging

Formats, precedence, and security handling are DESIGN.md §7. In Go:

- **YAML only for the human-edited `config.yaml`**, with `go.yaml.in/yaml/v3` (never `gopkg.in/yaml.v3`). **JSON** (`encoding/json`) for everything Petravault writes.
- **Reject unknown keys** in `config.yaml` and schedule job files (fail closed).
- **Precedence is flags, then `PETRAVAULT_*` environment variables, then `config.yaml`, then built-in defaults.** Implement it explicitly in `internal/config`. No Viper (enforced by `depguard`).
- Secrets never come from `config.yaml`, job files, or command-line arguments. They come from the keystore, `PETRAVAULT_PASSWORD_COMMAND`, or a `0600` `PETRAVAULT_PASSWORD_FILE` (DESIGN.md §11.2).
- Client-side paths follow XDG, with platform equivalents on macOS and Windows (DESIGN.md §7). Keep path logic in one file of `internal/config` with unit tests.

```go
// Strict YAML: unknown keys fail the load (also catches a pasted "password:" entry).
dec := yaml.NewDecoder(r)
dec.KnownFields(true)
if err := dec.Decode(&file); err != nil {
	return Config{}, fmt.Errorf("parse config: %w", err)
}

// Explicit precedence: flag > environment > file > default.
cfg.LogLevel = cmp.Or(flags.LogLevel, os.Getenv("PETRAVAULT_LOG_LEVEL"), file.LogLevel, "info")
```

```go
// A password file must not be readable by group or others (Unix).
fi, err := os.Stat(path)
if err != nil {
	return "", fmt.Errorf("stat password file: %w", err)
}
if fi.Mode().Perm()&0o077 != 0 {
	return "", fmt.Errorf("password file %s: permissions %v too open, want 0600", path, fi.Mode().Perm())
}
```

Use zero-value-aware types (pointers such as `*bool`) for settings where the zero value is a legitimate
choice, so `cmp.Or` does not treat it as "unset".

### Logging

- Use `log/slog` with structured attributes and the `...Context` methods. Inject the logger; derive with `With`.
- **Never log passwords, key material, or chunk plaintext** (DESIGN.md §7). Secret types redact themselves (section 7).
- Scheduled runs log each attempt with job name, snapshot ID (if committed), duration, and error (DESIGN.md §11.1).
- Levels: `Debug` (detail), `Info` (state changes), `Warn` (recoverable), `Error` (needs attention).

---

## 13. CLI Conventions

Commands, flags, and exit codes are DESIGN.md §16. The CLI framework is `cobra` (DESIGN.md §6).

- Command functions are thin: parse flags, build dependencies, call into `internal/...`, return an error. No business logic in `cmd`.
- Use `RunE` and return errors. `main` prints the error once and maps it to an exit code (section 9).
- Results go to stdout through `cmd.OutOrStdout()`. Diagnostics and logs go to stderr. `forbidigo` blocks `fmt.Print*`.
- Global flags are `-r/--repository`, `--config`, `--identity`, `--log-level`. A repository is picked as `--repository`, then `PETRAVAULT_REPOSITORY`, then `default_repository` (DESIGN.md §7).
- Passwords are never accepted as flag values.
- Test commands with `cmd.SetArgs`, `cmd.SetOut`, and `cmd.SetErr`.
- Adding or changing a flag or exit code also changes DESIGN.md §16, and is a breaking change under COMMIT_GUIDE.md when it removes or renames something.

```go
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "petravault",
		SilenceUsage:  true,
		SilenceErrors: true, // main prints the error once and maps it to an exit code
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	})
	root.PersistentFlags().StringP("repository", "r", "", "repository path or s3:bucket[/prefix]")
	root.PersistentFlags().String("config", "", "path to config.yaml")
	root.PersistentFlags().String("identity", "", "identity to use")
	root.PersistentFlags().String("log-level", "", "debug, info, warn, error")
	return root
}
```

---

## 14. Testing

The strategy and the attack table are DESIGN.md §13. Where and how to write the tests:

- **Unit tests** are `_test.go` files beside the code. Use `package foo_test` for black-box tests.
- **Cross-package suites:** the attack-simulation suite lives in `tests/attack`
  (one test per row of the table above). The `Repository` contract suite lives
  in `internal/repository` and runs against both backends; the S3 side runs in
  CI's integration job against a local S3-compatible server and is skipped
  locally unless `PETRAVAULT_TEST_S3_ENDPOINT` is set.
- **Every row of the attack-simulation table (DESIGN.md §13) has a test**, named after the attack. A PR that touches crypto, trust, restore, locks, or the scheduler adds or extends one.
- **Known-answer tests** for BLAKE3 and X-Wing key slots. **Golden-boundary tests** for chunking with a fixed key and checked-in offsets in `internal/chunking/testdata/` (DESIGN.md §3.3).
- **Fuzz** the chunker (structural invariants) and any parser of untrusted bytes: manifests, envelopes, pack headers.
- **One contract suite for `Repository`**, run against `LocalRepository` and `S3Repository`. S3 runs against a local S3-compatible test server and is skipped unless `PETRAVAULT_TEST_S3_ENDPOINT` is set.
- Use `testing/synctest` for scheduler retry, backoff, catch-up, and lock TTL logic so tests never sleep for real time.
- Table-driven tests with `t.Run`; `t.Helper()`, `t.Cleanup`, `t.TempDir()`, `t.Setenv()`, `t.Context()`; `t.Parallel()` where tests are independent.
- Tests use generated keys or fixed test vectors. Never real credentials, never a real repository.

```go
func FuzzChunker(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		chunks := chunkAll(t, data) // helper around the Chunker interface, fixed test key
		for i, c := range chunks {
			last := i == len(chunks)-1
			if len(c) > MaxSize || (len(c) < MinSize && !last) {
				t.Fatalf("chunk %d has size %d, want within [%d, %d]", i, len(c), MinSize, MaxSize)
			}
		}
		if !bytes.Equal(slices.Concat(chunks...), data) {
			t.Fatal("chunks do not concatenate back to the input")
		}
	})
}
```

```go
func TestRepositoryContract(t *testing.T) {
	backends := map[string]func(t *testing.T) repository.Repository{
		"local": newLocalRepo,
		"s3":    newS3Repo, // skips unless PETRAVAULT_TEST_S3_ENDPOINT is set
	}
	for name, newRepo := range backends {
		t.Run(name, func(t *testing.T) {
			repotest.Run(t, newRepo) // shared suite: PutObjectIfAbsent, GetRange, List, ...
		})
	}
}
```

---

## 15. Dependencies and Licensing

The approved list, the "do not use" list, and the licensing policy are DESIGN.md §6. Process:

1. Prefer the standard library.
2. Before adopting any module, check its license is compatible with **GPL-3.0-only** (BSD, MIT, ISC, Apache-2.0 are; GPL-2.0-only, source-available, and proprietary are not).
3. Check it is maintained: the "Published" date on `pkg.go.dev` and the real commit and release history. Nothing last updated more than about 12 months ago without an active maintainer. Re-check at each major version bump (DESIGN.md §6).
4. State the reason in the PR description. Dependency changes use `build(deps):` commits (COMMIT_GUIDE.md).
5. Wrap third-party code behind a small interface at the boundary.
6. Never add a second implementation of something already covered (for example a second BLAKE3 library).

Versions are pinned in `go.mod` and change only through reviewed PRs. A bot may open the PRs; a human merges them.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: build
      include: scope
    groups:
      minor-and-patch:
        update-types: [minor, patch]
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: ci
      include: scope
```

---

## 16. Documentation

- `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `DESIGN.md`, and `docs/{architecture,cryptography,threat-model,trust-model,storage,unattended}.md` are listed in DESIGN.md §14. Keep them in step with the code.
- Behavior changes update `DESIGN.md` (and the matching `docs/` file) in the same PR.
- Every package has a package comment. Every exported identifier has a doc comment starting with its name.
- Use runnable `Example` functions for stable APIs; they double as tests.
- Record significant decisions that deviate from or extend DESIGN.md in the PR description and the matching `docs/` file.

---

## 17. Commits and Pull Requests

Commit format, types, **scopes**, breaking-change rules, commit size, squash-merge rules, and the
**no-tool-attribution** rule are all in [COMMIT_GUIDE.md](COMMIT_GUIDE.md), which follows
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/). Nothing about commits
is repeated here.

Go-specific reminders:

- Modernization and formatting-only changes (from `go fix` or `modernize`) are their own commits.
- A dependency change is `build(deps):`; a CI change is `ci:`.
- A removed or renamed CLI command or flag, a changed exit code, a removed or renamed config key or environment variable, or a change to the on-disk repository format or crypto suite identifiers is **breaking** (COMMIT_GUIDE.md).
- Keep PRs small and tied to one phase or topic of DESIGN.md §15 where possible.
- PR description: what changed, why, how it was tested, and the DESIGN.md sections it touches.

---

## 18. Release Builds

DESIGN.md §13 requires reproducible-aim builds and release artifacts published with checksums, a
build-provenance attestation, and an SBOM.

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty)" \
  -o bin/petravault ./cmd/petravault
```

- `-trimpath`, `CGO_ENABLED=0`, and a pinned Go toolchain (the `go` line in `go.mod`) are the baseline for reproducibility.
- Publish `SHA256SUMS`, a Sigstore build-provenance attestation over the artifacts (`actions/attest`, no keys to manage), and an SBOM (for example CycloneDX via `cyclonedx-gomod`). Users verify with `gh attestation verify` and `sha256sum -c SHA256SUMS`.
- Tags use SemVer. Because commits follow Conventional Commits, tools such as `git-cliff` or `release-please` can derive the version bump (`feat` is MINOR, `fix` is PATCH, breaking is MAJOR) and the changelog.

---

## 19. Pull Request Checklist

- [ ] `make check` passes locally (format, vet, lint, race tests, build, govulncheck, license, REUSE)
- [ ] `go mod tidy` leaves no diff
- [ ] Modern idioms applied per the JetBrains guidelines (section 3)
- [ ] Every new file has the REUSE header; `reuse lint` is clean
- [ ] No dependency outside DESIGN.md §6 (or it is justified and license-checked)
- [ ] No hand-written crypto primitive; `crypto/rand` for all randomness
- [ ] Verify-before-use order kept; unknown config keys rejected
- [ ] Integrity failures wrap `ErrIntegrity` and map to exit code 4
- [ ] No secrets in logs, arguments, config, or error text
- [ ] Anything hashed or signed is built from deterministic bytes
- [ ] Contexts propagated; goroutines have an owner and a stop condition
- [ ] Tests added or updated, including an attack test where relevant; `-race` clean
- [ ] `DESIGN.md` and `docs/` updated if behavior changed
- [ ] Commits and PR title follow COMMIT_GUIDE.md, with no tool attribution
- [ ] Relevant items of DESIGN.md §17 (Definition of Done) still hold

---

## 20. Instructions for AI Coding Agents

When writing or modifying Go in this repository:

1. Read `DESIGN.md` for the area you are touching before writing code, and `COMMIT_GUIDE.md` before committing. Follow what they say; do not restate or contradict them.
2. Read `go.mod` and use only features available in that Go version.
3. Use the JetBrains Modern Go Guidelines (section 3): run `list --file-path <file>` before editing, read the **complete** output, and `explain <id>` before skipping a guideline.
4. Do not add dependencies, and do not implement cryptographic primitives. Use the libraries in DESIGN.md §6.
5. Where DESIGN.md says to verify an API "at adoption time" (for example the `go-cdc-chunkers` options), read the library's current documentation before coding against it.
6. After changes run `make check`, and fix everything it reports.
7. Commit messages follow COMMIT_GUIDE.md exactly. **Never add `Co-authored-by`, `Assisted-by`, or any mention of an AI tool** to a commit message, author, or committer field.
8. Keep changes minimal and focused. Do not reformat or refactor unrelated code.
9. If the task conflicts with DESIGN.md or this guide, or DESIGN.md is ambiguous, say so and ask instead of choosing silently.

---

## References

- Design: [DESIGN.md](DESIGN.md)
- Commits: [COMMIT_GUIDE.md](COMMIT_GUIDE.md), based on https://www.conventionalcommits.org/en/v1.0.0/
- JetBrains Modern Go Guidelines: https://github.com/JetBrains/go-modern-guidelines
- Effective Go: https://go.dev/doc/effective_go
- Go Code Review Comments: https://go.dev/wiki/CodeReviewComments
- golangci-lint: https://golangci-lint.run
- govulncheck: https://go.dev/doc/security/vuln/
- REUSE: https://reuse.software/
