<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# AGENTS.md — Instructions for Coding Agents

Entry file for AI/human contributors writing code here. Authority order:

1. `docs/DESIGN.md` for **behavior**. If it conflicts with any other doc about
   behavior, DESIGN wins. Behavior changes update DESIGN in the same PR.
2. `docs/GO_GUIDELINES.md` for **Go style, tooling, CI**.
3. `docs/COMMIT_GUIDE.md` for **commit messages** (Conventional Commits 1.0.0).

## Before writing Go

1. Read the DESIGN section for the area you touch.
2. Read `go.mod` and use only features available in that Go version (1.27+).
3. Run the JetBrains skill listing for each file before editing it
   (`docs/GO_GUIDELINES.md` §3) and read the complete output.

## Hard rules

- Compose approved libraries only (`docs/DESIGN.md` §6). Never hand-roll crypto,
  never add a dependency without a written reason + license check + reviewed PR.
- Every new file carries the REUSE header
  (`SPDX-FileCopyrightText:` + `SPDX-License-Identifier: GPL-3.0-only`);
  `reuse lint` must be clean.
- Fail closed: reject unknown config keys, never use unverified data, never
  swallow integrity failures (they wrap `ErrIntegrity`, exit code 4).
- No secrets in logs, arguments, config files, or error text.
- Verify-before-use order: signature → trust → history → chunks → write.
- Keep changes minimal and focused; no unrelated reformats.
- Run `make check` and fix everything it reports.
- Commits follow `docs/COMMIT_GUIDE.md` exactly. **Never** add
  `Co-authored-by`, `Assisted-by`, or any AI-tool mention to messages,
  authors, or committers.
- If the task conflicts with DESIGN or is ambiguous, stop and ask instead of
  choosing silently.
