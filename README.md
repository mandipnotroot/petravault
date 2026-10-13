<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Petravault — Secure Incremental Backup CLI

Secure, incremental, content-addressed backup with hybrid classical/post-quantum
key protection, signed snapshots, tamper detection, Reed-Solomon erasure coding,
built-in scheduling, and verification. Local filesystem + S3-compatible storage.

Status: **design phase**. This repository currently contains the design docs and
licensing scaffolding; implementation follows `docs/DESIGN.md` §15 (phases).
There is no usable binary yet.

## Docs

- Design/behavior (authority): `docs/DESIGN.md`
- Go rules: `docs/GO_GUIDELINES.md`
- Commits: `docs/COMMIT_GUIDE.md`
- Agent entrypoint: `AGENTS.md`
- Contributing: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`

## Prerequisites

- Go 1.27+ (`go version`)
- `pipx` (for the REUSE tool) + Node.js `npx` (for the Go-guidelines skill)

See `CONTRIBUTING.md` for install commands.

## Common commands (once Phase 1 scaffolding lands)

```bash
make check   # fmt, vet, lint, test, build, vuln, license, reuse — run before every PR
make test    # go test -race -shuffle=on ./...
make reuse   # reuse lint (REUSE compliance)
```

## License

GPL-3.0-only. The repository is [REUSE](https://reuse.software/) compliant:
every file carries `SPDX-FileCopyrightText:` + `SPDX-License-Identifier:`,
license texts live in `LICENSES/`, and `reuse lint` is clean in CI.
