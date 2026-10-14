<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Unattended Backups

Scheduling shares the exact manual backup pipeline; only schedules, retry,
and retention are added (`DESIGN.md` §11). Code: `internal/scheduler/`,
`internal/config/`, `cmd/petravault/schedule.go`.

## Commands

```bash
petravault schedule add --name daily-documents --source ~/Documents \
  --repository s3:my-backups --daily 02:00 \
  --keep-daily 30 --keep-weekly 12 --keep-monthly 12
petravault schedule list
petravault schedule status
petravault schedule run                 # due jobs once (cron entry every few minutes)
petravault schedule run daily-documents # one job immediately
petravault schedule enable|disable|remove daily-documents
petravault schedule daemon              # foreground loop (systemd, launchd, service, container)
petravault schedule daemon --interval 30s
```

`add` needs exactly one of `--daily HH:MM`, `--weekly "WD HH:MM"`, or
`--hourly`, plus `--name` and `--source`. Optional: `--repository`,
`--source-id`, `--identity`, `--ecc`, `--keep-daily/--keep-weekly/--keep-monthly`,
`--verify/--no-verify`, `--retry N` (default 3, max 10), `--disabled`.

Job definition example (`$XDG_CONFIG_HOME/petravault/schedule/*.json`):

```json
{
  "name": "daily-documents",
  "source": "/home/user/Documents",
  "repository": "s3:my-backups",
  "frequency": "daily", "time": "02:00",
  "retention": {"daily": 30, "weekly": 12, "monthly": 12},
  "verify": true, "enabled": true
}
```

## Semantics

- **State** (`$XDG_STATE_HOME/petravault/schedule/*.state.json`):
  `last_run`, `last_success`, `last_failure`, `failure_count`, `next_run`.
- **Next run** is strictly after now (daily/weekly wall-clock, hourly
  top-of-hour). A job still running is never started again (local advisory
  lock; Unix `flock`, Windows `O_EXCL` with stale reap).
- **Missed runs** collapse to one catch-up run, never one per missed
  interval.
- **Retry** is bounded exponential backoff (`30s << attempt`, capped at
  10 min). Only non-usage errors retry; a failed attempt never leaves a
  partial snapshot because commit is atomic.
- **Retention:** after a successful backup, `prune` runs with the job's
  keep settings under the maintenance lock. If the lock is held, the job
  skips pruning and logs it rather than failing the backup.
- **Verification:** `"verify": true` runs verify-after-backup on the new
  snapshot; otherwise the global `verify_after_backup` setting applies.
- **Logging/exit:** every attempt logs job name, snapshot ID if committed,
  duration, and error. `schedule run` exits non-zero when any job failed.

## Unattended unlock

Scheduled jobs cannot prompt. The keystore unlock order is fixed:

1. `PETRAVAULT_PASSWORD_COMMAND`: prints the password
   (`secret-tool`, `pass`, cloud secret managers, keyring).
2. `PETRAVAULT_PASSWORD_FILE`: file must be mode `0600`, refused otherwise.
3. Interactive prompt (manual runs only).

Passwords never live in `config.yaml` or job files and are never passed as
CLI arguments. Give scheduled machines a dedicated identity so it can be
revoked alone.

## Configuration

`$XDG_CONFIG_HOME/petravault/config.yaml` (strict: unknown keys fail load):

```yaml
default_repository: s3:my-backups
log_level: info
concurrency: 4
default_identity: alice
ecc: medium               # off | low | medium | high | <N>%
s3:
  profile: personal
  region: us-east-1
verify_after_backup: true
```

Precedence everywhere: CLI flags → `PETRAVAULT_*` environment
(`PETRAVAULT_REPOSITORY`, `PETRAVAULT_LOG_LEVEL`, `PETRAVAULT_IDENTITY`,
`PETRAVAULT_ECC`, `PETRAVAULT_S3_PROFILE`, `PETRAVAULT_S3_REGION`,
`PETRAVAULT_VERIFY_AFTER_BACKUP`, `PETRAVAULT_CONFIG`) → `config.yaml` →
built-ins (log `info`, concurrency 4, ECC `medium`, verify-after `true`).
Override the file with `PETRAVAULT_CONFIG` or `--config`. Repository
selection (every command except `init`): `--repository`, then
`PETRAVAULT_REPOSITORY`, then `default_repository`. Group/world-readable
`config.yaml` warns; job files must be `0600` and are permission-checked at
load. No secrets belong in either file.

## Systemd example

```ini
[Service]
Environment=PETRAVAULT_PASSWORD_FILE=%h/.config/petravault/pw
ExecStart=/usr/local/bin/petravault schedule daemon
Restart=on-failure
```

Prefer `schedule daemon` under a supervisor, or `schedule run` from cron
every few minutes. Either way, jobs share the manual pipeline, so there is
no weaker unattended code path.
