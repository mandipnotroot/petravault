# SPDX-FileCopyrightText: 2026 Petravault Contributors
# SPDX-License-Identifier: GPL-3.0-only

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

# Needs a local S3-compatible server, see GO_GUIDELINES.md section 14
test-integration:
	go test $(TESTFLAGS) -tags=integration ./...

fuzz:
	go test -run='^$$' -fuzz=FuzzChunker -fuzztime=30s ./internal/chunking

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vuln:
	go tool govulncheck ./...

# Only GPL-3.0-compatible licenses (DESIGN.md §6): permissive licenses plus
# GPL-3.0-only itself. --ignore drops the scanned module's own packages, so
# the project's own GPL-3.0-only license (governed by REUSE, see reuse
# target) is not judged as a dependency; GPL-3.0 without the -only qualifier
# stays rejected.
license:
	go run github.com/google/go-licenses@latest check ./... --ignore petravault \
		--allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,ISC,Apache-2.0,GPL-3.0-only

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
