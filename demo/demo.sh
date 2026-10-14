#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Petravault Contributors
# SPDX-License-Identifier: GPL-3.0-only
#
# Petravault end-to-end demo (DESIGN.md §15 phase 13, §17 Definition of Done).
#
# Walks the Definition of Done with the real CLI against throwaway local
# repositories: identity -> init -> backup -> modify -> incremental backup
# (unchanged files skipped) -> schedule a job -> verify -> Reed-Solomon
# maintenance and fault injection -> second member via key slot -> concurrent
# backups -> tamper detection -> unauthorized-signer rejection -> rollback
# detection -> prune with retention -> restore -> byte-identical diff.
#
# Everything runs under isolated HOME/XDG directories, so the demo never
# touches the operator's real ~/.config, keystore, or trust list. The only
# host side effects are the demo workspace (removed on success) and the
# built binary. Repositories are local paths; no S3 account is needed.
#
# Usage:
#   ./demo/demo.sh                 # build if needed, run, clean up
#   PETRAVAULT_BIN=/path/to/petravault ./demo/demo.sh
#
# Exit status is 0 only when every asserted step behaves as specified.

set -euo pipefail
shopt -s nullglob

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PETRAVAULT_BIN:-$ROOT/bin/petravault}"

# DEMO_PASSWORD is a throwaway value for demo-only repositories. It is not a
# real secret; every key and repository created here is deleted afterwards.
DEMO_PASSWORD="petravault-demo-password-only"

DEMO="$(mktemp -d "${TMPDIR:-/tmp}/petravault-demo-XXXXXX")"
ALICE_HOME="$DEMO/alice-home"
BOB_HOME="$DEMO/bob-home"
MALLORY_HOME="$DEMO/mallory-home"
REPO="$DEMO/repo"
SRC="$DEMO/src"
SCHED_SRC="$DEMO/sched-src"
BOB_SRC="$DEMO/bob-src"
SCRATCH_REPO="$DEMO/scratch-repo"
SCRATCH_SRC="$DEMO/scratch-src"
RESTORED="$DEMO/restored"
PARTIAL="$DEMO/partial"

cleanup() {
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "demo FAILED; workspace kept at $DEMO for inspection" >&2
    else
        rm -rf "$DEMO"
        echo "demo workspace cleaned"
    fi
    exit $rc
}
trap cleanup EXIT

die() {
    echo "demo FAILED: $*" >&2
    exit 1
}

say() {
    echo ""
    echo "### $*"
}

# use_client <home> switches every client-side input the CLI reads: keystore,
# trust list, head records, schedule jobs, and the unattended-unlock password
# file (DESIGN.md §7, §11.2). Each "machine" in the demo gets its own home.
use_client() {
    export HOME="$1"
    export XDG_CONFIG_HOME="$1/.config"
    export XDG_DATA_HOME="$1/.local/share"
    export XDG_STATE_HOME="$1/.local/state"
    export XDG_CACHE_HOME="$1/.cache"
    export PETRAVAULT_CONFIG=""
    export PETRAVAULT_REPOSITORY=""
    export PETRAVAULT_PASSWORD_COMMAND=""
    export PETRAVAULT_PASSWORD_FILE="$1/pw"
    mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME"
    printf '%s\n' "$DEMO_PASSWORD" > "$1/pw"
    chmod 600 "$1/pw"
}

# expect_fail <command...> runs a command that must fail (any non-zero exit).
expect_fail() {
    code=0
    "$@" >"$DEMO/last.log" 2>&1 || code=$?
    if [ "$code" -eq 0 ]; then
        echo "--- unexpected success ---" >&2
        cat "$DEMO/last.log" >&2
        die "expected failure from: $*"
    fi
    echo "(expected failure, exit $code: $*)"
}

# expect_code <want> <command...> runs a command that must fail with a
# specific exit code (2 usage, 4 integrity/trust per DESIGN.md §16).
expect_code() {
    want="$1"
    shift
    code=0
    "$@" >"$DEMO/last.log" 2>&1 || code=$?
    if [ "$code" -ne "$want" ]; then
        echo "--- unexpected output (want exit $want, got $code) ---" >&2
        cat "$DEMO/last.log" >&2
        die "expected exit $want from: $*"
    fi
    echo "(expected exit $want: $*)"
}

snapshot_of() {
    awk '/^snapshot /{print $2}' "$1"
}

first_object() {
    # First object in a repository family (packs/, indexes/, snapshots/),
    # excluding parity sidecars.
    for k in "$1"/"$2"/*; do
        case "$k" in
            *.ecc) continue ;;
            *) basename "$k"; return 0 ;;
        esac
    done
    return 1
}

corrupt_byte() {
    # corrupt_byte <file> <offset>: overwrite one byte, staying inside a
    # single Reed-Solomon shard so the damage is within the parity budget.
    printf '\xA5' | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc status=none
}

say "setup: build the binary if needed"
if [ ! -x "$BIN" ]; then
    (cd "$ROOT" && CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X main.version=demo" \
        -o "$BIN" ./cmd/petravault)
fi
"$BIN" version

mkdir -p "$SRC" "$SCHED_SRC" "$BOB_SRC" "$SCRATCH_SRC" "$RESTORED" "$PARTIAL"
use_client "$ALICE_HOME"

say "1. identity: create alice (also self-trusts)"
"$BIN" identity create --name alice | tee "$DEMO/alice-create.log"
FP_ALICE="$(awk '/^fingerprint:/{print $2}' "$DEMO/alice-create.log")"
[ -n "$FP_ALICE" ] || die "empty alice fingerprint"

say "2. repository: init with the default medium ECC profile"
"$BIN" init "$REPO" | tee "$DEMO/init.log"
grep -q "medium" "$DEMO/init.log" || die "init did not report the medium profile"
"$BIN" info -r "$REPO" | tee "$DEMO/info.log"
grep -q "ecc: medium" "$DEMO/info.log" || die "info did not show the medium profile"

say "3. backup: first backup commits one signed snapshot object"
echo "quarterly report" > "$SRC/report.txt"
echo "unchanged reference" > "$SRC/reference.txt"
# Settle file mtimes outside the 2s racily-clean window (DESIGN.md §3.4) so
# the next chapter's unchanged file is genuinely skipped, not re-read.
sleep 3
"$BIN" backup "$SRC" -r "$REPO" --source-id alice-laptop --verify | tee "$DEMO/backup1.log"
SNAP1="$(snapshot_of "$DEMO/backup1.log")"
[ -n "$SNAP1" ] || die "first backup printed no snapshot id"
grep -q "verify: ok" "$DEMO/backup1.log" || die "verify-after-backup did not run"
"$BIN" snapshots list -r "$REPO" | tee "$DEMO/list1.log"
grep -q "$SNAP1" "$DEMO/list1.log" || die "snapshot list misses $SNAP1"
"$BIN" snapshots show "$SNAP1" -r "$REPO" | tee "$DEMO/show1.log"
grep -q "alice-laptop" "$DEMO/show1.log" || die "snapshot show misses the source id"

say "4. incremental: modify one file, keep one file, reuse its chunks"
echo "quarterly report, revised" > "$SRC/report.txt"
sleep 1
"$BIN" backup "$SRC" -r "$REPO" --source-id alice-laptop | tee "$DEMO/backup2.log"
SNAP2="$(snapshot_of "$DEMO/backup2.log")"
[ -n "$SNAP2" ] || die "second backup printed no snapshot id"
[ "$SNAP2" != "$SNAP1" ] || die "second backup reused the snapshot id"
grep -Eq "reused: [1-9][0-9]*" "$DEMO/backup2.log" || die "unchanged file was not skipped: $(cat "$DEMO/backup2.log")"

say "5. verification: standard and deep"
"$BIN" verify -r "$REPO" | tee "$DEMO/verify.log"
grep -q "verify: ok" "$DEMO/verify.log" || die "standard verify failed"
"$BIN" verify --deep -r "$REPO" | tee "$DEMO/verify-deep.log"
grep -q "deep verify: ok" "$DEMO/verify-deep.log" || die "deep verify failed"

say "6. scheduling: add a job, run it immediately with unattended unlock"
echo "scheduled notes" > "$SCHED_SRC/notes.txt"
"$BIN" schedule add --name demo-daily --source "$SCHED_SRC" -r "$REPO" \
    --source-id demo-sched --daily 02:00 --verify | tee "$DEMO/sched-add.log"
grep -q 'added job "demo-daily"' "$DEMO/sched-add.log" || die "schedule add failed"
"$BIN" schedule list | tee "$DEMO/sched-list.log"
grep -q "demo-daily" "$DEMO/sched-list.log" || die "schedule list misses the job"
"$BIN" schedule status | tee "$DEMO/sched-status.log"
grep -q "demo-daily" "$DEMO/sched-status.log" || die "schedule status misses the job"
"$BIN" schedule run demo-daily | tee "$DEMO/sched-run.log"
SCHED_SNAP="$(awk '/^job /{print $4}' "$DEMO/sched-run.log")"
[ -n "$SCHED_SNAP" ] && [ "$SCHED_SNAP" != "none" ] || die "scheduled run committed no snapshot"

say "7. second member: bob joins via a granter-signed key slot"
use_client "$BOB_HOME"
"$BIN" identity create --name bob | tee "$DEMO/bob-create.log"
FP_BOB="$(awk '/^fingerprint:/{print $2}' "$DEMO/bob-create.log")"
[ -n "$FP_BOB" ] || die "empty bob fingerprint"
"$BIN" identity export "$FP_BOB" --output "$DEMO/bob.pub"
use_client "$ALICE_HOME"
"$BIN" identity import "$DEMO/bob.pub" | tee "$DEMO/bob-import.log"
grep -q "$FP_BOB" "$DEMO/bob-import.log" || die "bob fingerprint mismatch on import"
"$BIN" trust add "$FP_BOB" -r "$REPO" --grant-access | tee "$DEMO/grant.log"
grep -q "granted access" "$DEMO/grant.log" || die "grant-access failed"
"$BIN" identity export "$FP_ALICE" --output "$DEMO/alice.pub"
use_client "$BOB_HOME"
"$BIN" identity import "$DEMO/alice.pub" > /dev/null
"$BIN" trust add "$FP_ALICE" > /dev/null
echo "shared dataset" > "$BOB_SRC/shared.txt"

say "8. concurrency: alice and bob back up to one repository at once"
( use_client "$ALICE_HOME"
  "$BIN" backup "$SRC" -r "$REPO" --source-id alice-laptop --no-verify \
) >"$DEMO/alice3.log" 2>&1 &
P_ALICE=$!
( use_client "$BOB_HOME"
  "$BIN" backup "$BOB_SRC" -r "$REPO" --source-id bob-laptop \
) >"$DEMO/bob-backup.log" 2>&1 &
P_BOB=$!
wait $P_ALICE || die "alice concurrent backup failed (see $DEMO/alice3.log)"
wait $P_BOB || die "bob concurrent backup failed (see $DEMO/bob-backup.log)"
SNAP3="$(snapshot_of "$DEMO/alice3.log")"
BSNAP="$(snapshot_of "$DEMO/bob-backup.log")"
[ -n "$SNAP3" ] && [ -n "$BSNAP" ] || die "concurrent backups printed no snapshot ids"
use_client "$ALICE_HOME"
"$BIN" snapshots list -r "$REPO" | tee "$DEMO/list2.log"
grep -q "alice-laptop" "$DEMO/list2.log" || die "alice source missing after concurrent backups"
grep -q "bob-laptop" "$DEMO/list2.log" || die "bob source missing after concurrent backups"
"$BIN" verify -r "$REPO" > /dev/null || die "verify failed after concurrent backups"

say "9. erasure coding: lost sidecar is warned about, then regenerated"
# verify reports missing parity sidecars for index and snapshot objects.
IDX="$(first_object "$REPO" indexes)"
[ -n "$IDX" ] || die "no index object found"
rm "$REPO/indexes/$IDX.ecc"
"$BIN" verify -r "$REPO" | tee "$DEMO/sidecar.log"
grep -q "missing sidecar" "$DEMO/sidecar.log" || die "verify did not warn about the missing sidecar"
"$BIN" ecc rebuild -r "$REPO" | tee "$DEMO/rebuild.log"
grep -q "rebuilt erasure protection" "$DEMO/rebuild.log" || die "ecc rebuild failed"
"$BIN" verify --deep -r "$REPO" | tee "$DEMO/verify-deep2.log"
grep -q "deep verify: ok" "$DEMO/verify-deep2.log" || die "deep verify failed after rebuild"

say "10. fault injection on a scratch repository"
"$BIN" init "$SCRATCH_REPO" > /dev/null
echo "scratch data" > "$SCRATCH_SRC/data.txt"
"$BIN" backup "$SCRATCH_SRC" -r "$SCRATCH_REPO" --source-id scratch | tee "$DEMO/scratch1.log"
SSNAP1="$(snapshot_of "$DEMO/scratch1.log")"
[ -n "$SSNAP1" ] || die "scratch backup printed no snapshot id"

say "10a. tampered snapshot object is rejected (AEAD/signature, exit 4)"
SFILE="$SCRATCH_REPO/snapshots/$SSNAP1"
cp "$SFILE" "$DEMO/snap-pristine"
SSIZE="$(stat -c%s "$SFILE")"
corrupt_byte "$SFILE" "$((SSIZE / 2))"
rm -f "$SFILE.ecc"
expect_code 4 "$BIN" verify -r "$SCRATCH_REPO"
cp "$DEMO/snap-pristine" "$SFILE"
"$BIN" ecc rebuild -r "$SCRATCH_REPO" > /dev/null
"$BIN" verify --deep -r "$SCRATCH_REPO" > /dev/null || die "scratch repo did not recover"

say "10a2. damage within the parity budget is reconstructed and re-verified"
SPACK1="$(first_object "$SCRATCH_REPO" packs)"
[ -n "$SPACK1" ] || die "no scratch pack object found"
SPACK1FILE="$SCRATCH_REPO/packs/$SPACK1"
cp "$SPACK1FILE" "$DEMO/pack-pristine"
S1SIZE="$(stat -c%s "$SPACK1FILE")"
corrupt_byte "$SPACK1FILE" "$((S1SIZE / 2))"
expect_code 4 "$BIN" verify --deep -r "$SCRATCH_REPO"
# rebuild reconstructs the damaged shard in memory, AEAD-verifies the result,
# and writes fresh parity; it refuses to encode unverified data, so success
# proves Reed-Solomon recovery of the true bytes (DESIGN.md §4.5). Objects
# themselves are never rewritten, so the demo restores the pristine byte
# (standing in for an independent secondary copy) to keep going.
"$BIN" ecc rebuild -r "$SCRATCH_REPO" > /dev/null
cp "$DEMO/pack-pristine" "$SPACK1FILE"
"$BIN" verify --deep -r "$SCRATCH_REPO" > /dev/null || die "scratch repo did not recover"

say "10b. deleted newest snapshot is detected as rollback (exit 4)"
echo "scratch data, v2" > "$SCRATCH_SRC/data.txt"
sleep 1
"$BIN" backup "$SCRATCH_SRC" -r "$SCRATCH_REPO" --source-id scratch | tee "$DEMO/scratch2.log"
SSNAP2="$(snapshot_of "$DEMO/scratch2.log")"
[ -n "$SSNAP2" ] || die "second scratch backup printed no snapshot id"
rm -f "$SCRATCH_REPO/snapshots/$SSNAP2" "$SCRATCH_REPO/snapshots/$SSNAP2.ecc"
expect_code 4 "$BIN" verify -r "$SCRATCH_REPO"
grep -Ei "rollback|missing" "$DEMO/last.log" > /dev/null \
    || die "rollback detection mentions neither rollback nor a missing head"

say "10c. damage beyond the parity budget is unrecoverable, never silent"
SPACK="$(first_object "$SCRATCH_REPO" packs)"
[ -n "$SPACK" ] || die "no scratch pack object found"
SPACKFILE="$SCRATCH_REPO/packs/$SPACK"
SPSIZE="$(stat -c%s "$SPACKFILE")"
corrupt_byte "$SPACKFILE" 0
corrupt_byte "$SPACKFILE" "$((SPSIZE - 1))"
expect_code 4 "$BIN" ecc rebuild -r "$SCRATCH_REPO"
grep -q "exceed" "$DEMO/last.log" || die "rebuild did not report the exceeded budget"
expect_code 4 "$BIN" verify --deep -r "$SCRATCH_REPO"

say "11. unauthorized signer is rejected"
use_client "$MALLORY_HOME"
"$BIN" identity create --name mallory | tee "$DEMO/mallory-create.log"
FP_MALLORY="$(awk '/^fingerprint:/{print $2}' "$DEMO/mallory-create.log")"
[ -n "$FP_MALLORY" ] || die "empty mallory fingerprint"
expect_fail "$BIN" backup "$SRC" -r "$REPO" --source-id mallory
use_client "$ALICE_HOME"
# Corrupt a fully significant character (the first: only the final base32
# character has unused trailing bits, so a last-character change can alias
# the same fingerprint instead of mismatching).
case "$FP_BOB" in
a* | A*) BADFP="b${FP_BOB#?}" ;;
*) BADFP="a${FP_BOB#?}" ;;
esac
expect_code 4 "$BIN" trust add "$BADFP" --from "$DEMO/bob.pub" -r "$REPO"
grep -q "want" "$DEMO/last.log" || die "fingerprint mismatch was not reported"
"$BIN" trust list | tee "$DEMO/trust.log"
grep -q "$FP_MALLORY" "$DEMO/trust.log" && die "mallory is trusted, want untrusted"

say "12. retention: prune previews, then collects only unreferenced data"
"$BIN" prune --keep-daily 1 --dry-run -r "$REPO" | tee "$DEMO/prune-dry.log"
grep -q "dry run: no changes made" "$DEMO/prune-dry.log" || die "prune dry run misbehaved"
"$BIN" prune --keep-daily 1 -r "$REPO" | tee "$DEMO/prune.log"
grep -q "prune: ok" "$DEMO/prune.log" || die "prune failed"
"$BIN" snapshots list -r "$REPO" | tee "$DEMO/list3.log"
grep -q "alice-laptop" "$DEMO/list3.log" || die "prune removed the newest alice snapshot"
grep -q "bob-laptop" "$DEMO/list3.log" || die "prune removed the newest bob snapshot"
grep -q "demo-sched" "$DEMO/list3.log" || die "prune removed the newest scheduled snapshot"

say "13. restore: byte-identical output, plus a partial restore"
# SCHED_SNAP is demo-sched's newest snapshot, so retention always keeps it.
"$BIN" restore "$SCHED_SNAP" "$RESTORED" -r "$REPO"
diff -r "$SCHED_SRC" "$RESTORED" || die "restored tree differs from $SCHED_SRC"
"$BIN" restore "$SCHED_SNAP" "$PARTIAL" -r "$REPO" --include notes.txt
[ -f "$PARTIAL/notes.txt" ] || die "partial restore missed notes.txt"

say "14. final verification of the whole repository"
"$BIN" verify -r "$REPO" | tee "$DEMO/final.log"
grep -q "verify: ok" "$DEMO/final.log" || die "final verify failed"

echo ""
echo "demo OK: all chapters passed (see DESIGN.md §17 for the walked checklist)"
