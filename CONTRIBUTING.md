<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Contributing

## Prerequisites

Debian 13 (adjust the installer for your OS):

```bash
sudo apt update && sudo apt install -y git curl make pipx nodejs npm
pipx ensurepath
pipx install reuse
go version   # want Go 1.27+
```

Go dev tools (`golangci-lint`, `govulncheck`) come via the `tool`
directive in `go.mod` — no separate install. The Modern Go skill:

```bash
npx skills add JetBrains/go-modern-guidelines
```

## Workflow

1. Read `AGENTS.md`, then the `docs/DESIGN.md` section you touch.
2. Keep PRs small, one phase/topic (`docs/DESIGN.md` §15).
3. Behavior change → update `docs/DESIGN.md` (+ matching `docs/` file) in the
   same PR.
4. Run before pushing:
   ```bash
   make check   # fmt, vet, lint, test, build, vuln, license, reuse
   ```
5. Tests: unit tests beside the code; cross-package suites in
   `tests/{integration,security,attack}/`. Touching crypto, trust, restore,
   locks, or scheduler → add/extend an attack test (`docs/DESIGN.md` §13).

## Commits

Conventional Commits per `docs/COMMIT_GUIDE.md` (types, scopes in the table,
`!`/`BREAKING CHANGE:` for breaking changes). One logical change per commit.
**No AI-tool attribution** anywhere in messages, authors, or committers.

## Licensing

Contributions are GPL-3.0-only. New dependencies must be GPL-3.0-compatible
(BSD/MIT/ISC/Apache-2.0; never GPL-2.0-only, source-available, proprietary)
with a written reason and reviewed PR (`docs/DESIGN.md` §6). Every new file
needs the REUSE header; `reuse lint` must be clean.
