<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Petravault demo

End-to-end walkthrough of `docs/DESIGN.md` §17 (Definition of Done) with the
real CLI against throwaway local repositories. This is the `demo` item of
`docs/DESIGN.md` §15 phase 13.

## Run it

```bash
make demo
# or directly:
./demo/demo.sh
# with an existing binary:
PETRAVAULT_BIN=/path/to/petravault ./demo/demo.sh
```

The script builds `./bin/petravault` first when it is missing, runs fourteen
chapters, and asserts the expected outcome of each step (including the
expected exit codes: `4` for integrity/trust failures). Any surprise fails
the script. On success the workspace is deleted; on failure it is kept and
its path is printed for inspection.

Everything runs under isolated `HOME`/XDG directories per client machine
(alice, bob, mallory), so the demo never touches real keystores, trust
lists, or head records. Repositories are local paths; no S3 account needed.

## What it proves

| Chapter | Done item (DESIGN.md §17) |
|---|---|
| 1–2 | create identity → create repository |
| 3–4 | first backup → modify files → incremental backup (unchanged files skipped) |
| 5 | verification (`verify`, `verify --deep`) |
| 6 | schedule future backup (`schedule add/list/status/run`, unattended unlock via `PETRAVAULT_PASSWORD_FILE`) |
| 7–8 | add a second member via key slot → second machine backs up concurrently |
| 9–10 | delete/corrupt a shard → Reed-Solomon maintenance (`verify` warning, `ecc rebuild`, deep re-verification); within-budget detection plus beyond-budget unrecoverable error on a scratch repository |
| 10a–11 | tamper with encrypted data → integrity failure (exit 4); unauthorized signing incl. forged trust binding → rejected |
| 10b | delete the newest snapshot → rollback detected via head records (exit 4) |
| 12 | prune with retention (dry run, then real; newest snapshot of every source kept) |
| 13–14 | restore snapshot → byte-identical output (`diff -r`), partial restore, final verification |

True multi-process concurrency races, the full attack table, and S3
backends are covered by `tests/attack/` and the contract suites, not by
this script; the demo stays sequential except for the two-client backup in
chapter 8.
