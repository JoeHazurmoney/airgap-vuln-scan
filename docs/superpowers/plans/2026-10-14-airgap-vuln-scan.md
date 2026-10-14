# airgap-vuln-scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (Native: implemented
> inline in this session; the user said "go ahead and implement" and no subagents were asked
> for). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build issue #1: bash scripts that fetch the official Trivy and Grype images and their
databases, package a checksummed release, import it on either forge, and scan offline with an
age warning, plus a GitHub Actions workflow that proves every acceptance criterion.

**Architecture:** Five bash scripts in `scripts/` (`fetch`, `package`, `import`, `check-age`,
`scan`) share `scripts/lib.sh`. Every tool runs in its official image via `docker run`; the
host needs only bash, coreutils, sed, curl, tar, gzip and Docker. Unit tests run against a fake
`docker` on PATH (no Docker, no network); one CI job runs the real thing end to end, playing
both forges.

**Tech Stack:** bash, GNU coreutils, Docker, Trivy (`ghcr.io/aquasecurity/trivy:latest`), Grype
(`ghcr.io/anchore/grype:latest`), GitHub Actions, shellcheck.

**Spec:** `docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md` (approved 2026-10-14),
with `docs/architecture.md` and ADR-0001.

## Context

The user approved the spec on 2026-10-14 and asked one question: is `grype:debug` the right tag
or should it say `latest`? Answer (checked): Grype publishes floating `latest`, `nonroot` and
`debug` tags each release, each with a versioned twin; today `debug` = `v0.120.1-debug` and
`latest` = `v0.120.1`. `debug` only adds a busybox shell. These scripts run Grype with
`docker run`, so nothing here needs a shell. **Switch to `grype:latest`**; mention `debug` only
for forges that run jobs inside the scanner image (e.g. GitLab's Docker executor). Task 0 makes
that change in the docs.

Facts checked for this plan (2026-10-14): Trivy opens its DB read-only (`bolt.Options{ReadOnly:
true}`); Grype opens its DB with `mode=ro`; Trivy supports `--cache-backend memory` and
`trivy convert --format table`; Grype accepts several `-o FORMAT=FILE` outputs; Grype's `db list`
text prints `DB URL:` and `Checksum: sha256:…`, its `-o json` prints `"built"`.

## Global Constraints

- Straightforward example: no signing, attestations, SLSA, release machinery or wd2l-style gates.
- Official images, unchanged; defaults `ghcr.io/aquasecurity/trivy:latest`,
  `ghcr.io/anchore/grype:latest`; local tags `airgap-vuln-scan/trivy:<v>`,
  `airgap-vuln-scan/grype:<v>`; everything after the pull uses the pinned digest.
- Host needs: bash, coreutils, sed, curl, tar, gzip, Docker. **No jq, no Python.**
- Must run in Git Bash on the PC (Docker Desktop) and on Linux runners: `host_path` converts
  mount paths with `pwd -W`; `MSYS_NO_PATHCONV=1` on `docker run`; `* text=auto eol=lf`.
- Containers run as the host user: `--user "$(id -u):$(id -g)" -e HOME=/tmp`.
- `MANIFEST` is `KEY=value`, read with `sed`, **never sourced**; values used in paths or image
  references are pattern-checked.
- Age limits: `MAX_DB_AGE_DAYS` (trivy-db, grype-db) and `MAX_JAVA_DB_AGE_DAYS`
  (trivy-java-db), default 7; stale = built more than N × 24 h ago; warnings never fail.
- `--java-db-refresh-days N`, default 0 = every fetch.
- Wording: customer-neutral (say "customer"); tools named generically
  ("e.g. GitHub, GitLab").
- Commits: conventional messages, ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Pins: actions by SHA; images by digest (values in Task 7).

## Review Focus

Failure modes the spec implies but its acceptance tests don't exercise; each gets a test in the
owning task:
1. **Paths with spaces** (e.g. `C:\Users\First Last\…`): package and import must work → Task 4.
2. **An import that fails halfway** (a valid checksum on a broken archive): `current/` must stay
   untouched → Task 4.
3. **Scanning before anything is imported:** a clear "import a release first" error → Tasks 2, 5.
4. **`SHA256SUMS` written in binary mode** (`hash *file`, as some platforms do): still accepted
   → Task 4.
5. **Clock skew** (a database "built" in the future on the disconnected host): 0.0 days, no
   warning, no negative numbers → Task 2.

## File Structure

| File | Responsibility |
|---|---|
| `.gitattributes` | LF everywhere, so scripts survive a Windows checkout |
| `scripts/lib.sh` | shared helpers: log/die/warn, `manifest_get`, time math, `host_path`, `docker_run`, offline flag sets |
| `scripts/fetch.sh` | connected: pull and pin images, download the three databases, write `fetch.env` |
| `scripts/package.sh` | connected: build `scanners-YYYY-MM-DD/` with `MANIFEST` and `SHA256SUMS` |
| `scripts/import.sh` | both: verify, load (+push), unpack to `incoming/`, swap to `current/` |
| `scripts/check-age.sh` | both: print each database's age, warn past the limit |
| `scripts/scan.sh` | both: check-age, then Trivy and Grype with no network |
| `tests/run.sh` | test runner: each `test_*` in a fresh bash, temp dir, fake docker |
| `tests/helpers.sh` | asserts and fixtures (`make_vulndb`, `make_work`, `iso`) |
| `tests/stubs/docker` | fake docker: logs calls, answers `db status` and `save` |
| `tests/test_{lib,check_age,package,import,scan,fetch}.sh` | unit tests per script |
| `.github/workflows/demo.yml` | end-to-end proof of the acceptance criteria |
| `README.md`, `docs/architecture.md`, spec | `grype:latest`, walkthrough, Result |

---

### Task 0: Branch, plan copy, and the `grype:latest` docs change

**Files:** Create `docs/superpowers/plans/2026-10-14-airgap-vuln-scan.md` (a copy of this plan).
Modify `README.md`, `docs/architecture.md`, `docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md`.

- [ ] **Step 1:** `cd airgap-vuln-scan && git switch docs/issue-1-spec && git switch -c feat/issue-1-offline-scan`
- [ ] **Step 2:** Copy this plan to `docs/superpowers/plans/2026-10-14-airgap-vuln-scan.md`.
- [ ] **Step 3:** Replace the Grype debug references:
```bash
sed -i 's/grype:debug"\]/grype:latest"]/; s/trivy:latest · grype:debug/trivy:latest · grype:latest/' README.md docs/architecture.md docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md
sed -i 's|ghcr.io/anchore/grype:debug|ghcr.io/anchore/grype:latest|g; s|airgap-vuln-scan/grype:<version>-debug|airgap-vuln-scan/grype:<version>|g; s|grype-<v>-debug.tar.gz|grype-<v>.tar.gz|g; s|grype:0.120.1-debug|grype:0.120.1|g; s|PREFIX/grype:<v>-debug` and `PREFIX/grype:debug|PREFIX/grype:<v>` and `PREFIX/grype:latest|; s|is 9 days old|is 9.0 days old|; s|(Trivy, Grype debug, shellcheck)|(Trivy, Grype, shellcheck)|' docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md
sed -i 's|grype-0.120.1-debug.tar.gz|grype-0.120.1.tar.gz|' docs/architecture.md
grep -n debug README.md docs/architecture.md docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md
```
Expected remaining hits: only the spec's Background sentence about the `debug` variant.
- [ ] **Step 4:** In `docs/architecture.md`, after the GitLab `config.toml` block, add:
```markdown
If your forge runs each job inside the scanner image (e.g. GitLab's Docker executor) rather than
calling `docker run` from a shell, Grype's plain image has no shell to run the job. Set
`GRYPE_IMAGE_REF=ghcr.io/anchore/grype:debug`: the same release, plus a busybox shell.
```
- [ ] **Step 5:** Commit: `docs: use grype:latest, and the implementation plan (#1)`.

### Task 1: Test harness and `scripts/lib.sh`

**Files:** Create `.gitattributes`, `tests/run.sh`, `tests/helpers.sh`, `tests/stubs/docker`,
`tests/test_lib.sh`, `scripts/lib.sh`.

**Interfaces — Produces (lib.sh):** `log MSG` (stderr) · `die MSG` (stderr, exit 1) ·
`warn MSG` (stdout `WARNING: MSG`, plus `::warning title=Stale vulnerability database::MSG` when
`GITHUB_ACTIONS=true`) · `manifest_get FILE KEY [PATTERN]` · `to_epoch TIME` · `now_epoch`
(honours `AGE_CHECK_NOW`) · `days_since TIME` → `"7.5"` · `older_than TIME DAYS` (status) ·
`trivy_built METADATA_JSON` · `host_path PATH` · `docker_run ARGS…` · arrays `TRIVY_OFFLINE`,
`GRYPE_OFFLINE`. **Tests' helpers:** `fail`, `assert_eq`, `assert_contains`,
`assert_not_contains`, `iso DAYS_AGO`, `make_vulndb DIR TRIVY_DAYS JAVA_DAYS GRYPE_DAYS`,
`make_work DIR`; env `SCRIPTS`, `TMP`, `TESTS`, `FAKE_DOCKER_LOG`, `FAKE_GRYPE_BUILT`.

- [ ] **Step 1: The harness.** `.gitattributes`:
```
# Keep LF line endings everywhere, even in a Windows checkout: bash can't run CRLF scripts.
* text=auto eol=lf
```
`tests/run.sh`:
```bash
#!/usr/bin/env bash
# tests/run.sh [TEST_FILE...]: runs every test_* function in tests/test_*.sh (or the files
# given). Each test runs in a fresh bash with `set -euo pipefail`, in its own temporary
# directory, with a fake docker first on PATH, so no test needs Docker or a network.
set -uo pipefail
TESTS=$(cd "$(dirname "$0")" && pwd)
export TESTS
files=("$@")
[[ ${#files[@]} -gt 0 ]] || files=("$TESTS"/test_*.sh)
failures=0
for file in "${files[@]}"; do
  for t in $(sed -n 's/^\(test_[a-z0-9_]*\)().*/\1/p' "$file"); do
    TMP=$(mktemp -d)
    export TMP
    # shellcheck disable=SC2016 # expanded by the inner bash
    if (cd "$TMP" && bash -c 'set -euo pipefail; source "$TESTS/helpers.sh"; source "$1"; "$2"' _ "$file" "$t") > "$TMP.out" 2>&1; then
      printf 'ok    %s %s\n' "$(basename "$file")" "$t"
    else
      printf 'FAIL  %s %s\n' "$(basename "$file")" "$t"
      sed 's/^/      /' "$TMP.out"
      failures=$((failures + 1))
    fi
    rm -rf "$TMP" "$TMP.out"
  done
done
printf '%d failed\n' "$failures"
[[ $failures -eq 0 ]]
```
`tests/stubs/docker`:
```bash
#!/usr/bin/env bash
# Stand-in for docker in the unit tests: records each call in $FAKE_DOCKER_LOG, prints what the
# scripts read back, and succeeds. FAKE_GRYPE_BUILT is the build time `grype db status`
# reports; unset, the status fails, as it does when no database is installed.
printf '%s\n' "$*" >> "${FAKE_DOCKER_LOG:-/dev/null}"
case " $* " in
  *" db status "*)
    [[ -n ${FAKE_GRYPE_BUILT:-} ]] || exit 1
    printf '{\n "schemaVersion": "v6.1.10",\n "built": "%s",\n "path": "/db/grype/6/vulnerability.db"\n}\n' "$FAKE_GRYPE_BUILT" ;;
  " save "*)
    printf 'saved %s\n' "$2" ;;
esac
exit 0
```
`tests/helpers.sh`:
```bash
# Helpers for the unit tests, sourced by tests/run.sh before each test file.
# shellcheck shell=bash disable=SC2154 # TESTS and TMP come from tests/run.sh

SCRIPTS=$(cd "$TESTS/../scripts" && pwd)
export PATH="$TESTS/stubs:$PATH"
export FAKE_DOCKER_LOG=$TMP/docker.log
: > "$FAKE_DOCKER_LOG"
unset AGE_CHECK_NOW GITHUB_ACTIONS MAX_DB_AGE_DAYS MAX_JAVA_DB_AGE_DAYS TRIVY_IMAGE GRYPE_IMAGE FAKE_GRYPE_BUILT

fail() { printf '%s\n' "$*" >&2; return 1; }
assert_eq() { [[ $1 == "$2" ]] || fail "expected [$2], got [$1]"; }
assert_contains() { [[ $1 == *"$2"* ]] || fail "expected to find [$2] in:"$'\n'"$1"; }
assert_not_contains() { [[ $1 != *"$2"* ]] || fail "didn't expect [$2] in:"$'\n'"$1"; }

# iso DAYS_AGO: an ISO 8601 time DAYS_AGO days before now (negative: in the future).
iso() { date -u -d "@$(( $(date -u +%s) - $1 * 86400 ))" +%Y-%m-%dT%H:%M:%SZ; }

# make_vulndb DIR TRIVY_DAYS JAVA_DAYS GRYPE_DAYS: a database directory as import.sh leaves it,
# each database built that many days ago. Grype's build time comes from the fake docker.
make_vulndb() {
  mkdir -p "$1/trivy/db" "$1/trivy/java-db" "$1/grype"
  printf '{"Version":2,"NextUpdate":"%s","UpdatedAt":"%s","DownloadedAt":"%s"}' "$(iso -1)" "$(iso "$2")" "$(iso 0)" > "$1/trivy/db/metadata.json"
  printf '{"Version":1,"NextUpdate":"%s","UpdatedAt":"%s","DownloadedAt":"%s"}' "$(iso -1)" "$(iso "$3")" "$(iso 0)" > "$1/trivy/java-db/metadata.json"
  printf 'RELEASE=scanners-2026-10-14\nTRIVY_IMAGE=airgap-vuln-scan/trivy:0.75.0\nGRYPE_IMAGE=airgap-vuln-scan/grype:0.120.1\n' > "$1/MANIFEST"
  FAKE_GRYPE_BUILT=$(iso "$4")
  export FAKE_GRYPE_BUILT
}

# make_work DIR: what fetch.sh leaves in its WORK_DIR, with small fake databases.
make_work() {
  mkdir -p "$1/trivy/db" "$1/trivy/java-db"
  printf 'fake trivy db' > "$1/trivy/db/trivy.db"
  printf '{"Version":2,"UpdatedAt":"%s"}' "$(iso 1)" > "$1/trivy/db/metadata.json"
  printf 'fake java db' > "$1/trivy/java-db/trivy-java.db"
  printf '{"Version":1,"UpdatedAt":"%s"}' "$(iso 1)" > "$1/trivy/java-db/metadata.json"
  printf 'fake grype archive' > "$1/grype-db.tar.zst"
  cat > "$1/fetch.env" <<EOF
TRIVY_VERSION=0.75.0
TRIVY_SOURCE=ghcr.io/aquasecurity/trivy@sha256:$(printf '1%.0s' {1..64})
TRIVY_IMAGE=airgap-vuln-scan/trivy:0.75.0
GRYPE_VERSION=0.120.1
GRYPE_SOURCE=ghcr.io/anchore/grype@sha256:$(printf '2%.0s' {1..64})
GRYPE_IMAGE=airgap-vuln-scan/grype:0.120.1
TRIVY_DB_BUILT=$(iso 1)
TRIVY_JAVA_DB_BUILT=$(iso 1)
GRYPE_DB_BUILT=$(iso 1)
EOF
}
```
- [ ] **Step 2: Failing tests** — `tests/test_lib.sh`:
```bash
# Unit tests for scripts/lib.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

# lib FUNCTION ARGS...: runs a lib.sh function in its own bash.
# shellcheck disable=SC2016
lib() { bash -c 'source "$1"; shift; "$@"' _ "$SCRIPTS/lib.sh" "$@"; }

test_manifest_get_reads_a_value() {
  printf 'A=1\nTRIVY_VERSION=0.75.0\n' > m
  assert_eq "$(lib manifest_get m TRIVY_VERSION)" 0.75.0
}

test_manifest_get_fails_on_a_missing_key() {
  printf 'A=1\n' > m
  if out=$(lib manifest_get m B 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "B not found in m"
}

test_manifest_get_never_runs_the_file() {
  # shellcheck disable=SC2016
  printf 'X=$(touch ran)\n' > m
  # shellcheck disable=SC2016
  assert_eq "$(lib manifest_get m X)" '$(touch ran)'
  [[ ! -e ran ]] || fail "the manifest's content was executed"
}

test_manifest_get_rejects_a_value_that_does_not_match() {
  printf 'TRIVY_VERSION=../../etc\n' > m
  if out=$(lib manifest_get m TRIVY_VERSION '^[0-9A-Za-z._-]+$' 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "unexpected TRIVY_VERSION"
}

test_to_epoch_reads_trivy_and_grype_times() {
  assert_eq "$(lib to_epoch 2026-10-13T06:35:20Z)" 1791873320
  assert_eq "$(lib to_epoch 2026-10-13T06:35:20.123456789Z)" 1791873320
}

test_trivy_built_reads_updated_at() {
  printf '{"Version":2,"NextUpdate":"2026-10-14T00:00:00Z","UpdatedAt":"2026-10-13T06:20:16.5Z","DownloadedAt":"2026-10-13T07:00:00Z"}' > metadata.json
  assert_eq "$(lib trivy_built metadata.json)" 2026-10-13T06:20:16.5Z
}

test_trivy_built_fails_on_a_missing_file() {
  if out=$(lib trivy_built nowhere.json 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "nowhere.json not found"
}

test_days_since_counts_tenths_and_never_goes_negative() {
  export AGE_CHECK_NOW=2026-10-20T18:00:00Z
  assert_eq "$(lib days_since 2026-10-13T06:00:00Z)" 7.5
  assert_eq "$(lib days_since 2026-10-21T00:00:00Z)" 0.0
}

test_older_than_means_strictly_more_than_the_limit() {
  export AGE_CHECK_NOW=2026-10-20T06:00:00Z
  lib older_than 2026-10-13T05:59:59Z 7 || fail "7 days and 1 second is older than 7 days"
  if lib older_than 2026-10-13T06:00:00Z 7; then fail "exactly 7 days is not older than 7 days"; fi
}

test_warn_adds_an_annotation_on_github_actions() {
  assert_eq "$(lib warn old)" "WARNING: old"
  export GITHUB_ACTIONS=true
  assert_contains "$(lib warn old)" "::warning title=Stale vulnerability database::old"
}

test_host_path_gives_an_absolute_path_for_dirs_and_files() {
  mkdir "d d"; touch "d d/f"
  dir=$(lib host_path "d d")
  [[ $dir == /* || $dir == [A-Za-z]:/* ]] || fail "not absolute: $dir"
  assert_eq "$(lib host_path "d d/f")" "$dir/f"
}
```
- [ ] **Step 3:** `bash tests/run.sh tests/test_lib.sh` → every test FAILs (`lib.sh` missing).
- [ ] **Step 4: Implement** `scripts/lib.sh`:
```bash
# Shared helpers for the airgap-vuln-scan scripts. Sourced, not run.
# shellcheck shell=bash

set -euo pipefail

# log MESSAGE: progress, on stderr (stdout is kept for results).
log() { printf '%s\n' "$*" >&2; }

# die MESSAGE: an error on stderr, then exit 1.
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# warn MESSAGE: a WARNING line on stdout, plus an annotation on GitHub Actions.
warn() {
  printf 'WARNING: %s\n' "$*"
  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    printf '::warning title=Stale vulnerability database::%s\n' "$*"
  fi
}

# manifest_get FILE KEY [PATTERN]: KEY's value in a KEY=value file, which must match the
# extended regex PATTERN if one is given. Read with sed, never sourced: the file may have come
# from removable media.
manifest_get() {
  local value
  value=$(sed -n "s/^$2=//p" "$1" | head -n 1)
  [[ -n $value ]] || die "$2 not found in $1"
  [[ -z ${3:-} || $value =~ $3 ]] || die "unexpected $2 in $1: '$value'"
  printf '%s\n' "$value"
}

# to_epoch TIME: seconds since 1970 for an ISO 8601 time.
to_epoch() { date -u -d "$1" +%s; }

# now_epoch: the current time, or AGE_CHECK_NOW (an ISO 8601 time, for tests) if set.
now_epoch() {
  if [[ -n ${AGE_CHECK_NOW:-} ]]; then to_epoch "$AGE_CHECK_NOW"; else date -u +%s; fi
}

# days_since TIME: days since TIME, to a tenth ("7.5"); never negative.
days_since() {
  local age
  age=$(( $(now_epoch) - $(to_epoch "$1") ))
  (( age > 0 )) || age=0
  printf '%d.%d\n' $(( age / 86400 )) $(( age * 10 / 86400 % 10 ))
}

# older_than TIME DAYS: succeeds if TIME is more than DAYS × 24 hours ago.
older_than() { (( $(now_epoch) - $(to_epoch "$1") > $2 * 86400 )); }

# trivy_built METADATA_JSON: the UpdatedAt time in one of Trivy's metadata.json files.
trivy_built() {
  local built
  [[ -f $1 ]] || die "$1 not found; import a release first"
  built=$(sed -n 's/.*"UpdatedAt" *: *"\([^"]*\)".*/\1/p' "$1")
  [[ -n $built ]] || die "no UpdatedAt in $1"
  printf '%s\n' "$built"
}

# host_path PATH: PATH (a directory or a file) as an absolute path Docker can bind-mount.
# Git Bash needs the Windows form (C:/...), which `pwd -W` gives.
host_path() {
  local dir=$1 file=""
  if [[ ! -d $dir ]]; then file=/$(basename "$dir"); dir=$(dirname "$dir"); fi
  if (cd "$dir" && pwd -W) > /dev/null 2>&1; then
    dir=$(cd "$dir" && pwd -W)
  else
    dir=$(cd "$dir" && pwd)
  fi
  printf '%s%s\n' "$dir" "$file"
}

# docker_run ARGS...: docker run as the host user, so files written to bind mounts belong to
# the runner. MSYS_NO_PATHCONV stops Git Bash rewriting the container-side paths.
docker_run() {
  MSYS_NO_PATHCONV=1 docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp "$@"
}

# The settings that keep each scanner offline, with its databases mounted at /db. Used by the
# scripts that source this file.
# shellcheck disable=SC2034
TRIVY_OFFLINE=(--cache-dir /db/trivy --skip-db-update --skip-java-db-update --skip-check-update
  --offline-scan --skip-version-check --disable-telemetry)
# shellcheck disable=SC2034
GRYPE_OFFLINE=(-e GRYPE_DB_CACHE_DIR=/db/grype -e GRYPE_DB_AUTO_UPDATE=false
  -e GRYPE_DB_VALIDATE_AGE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false)
```
- [ ] **Step 5:** `bash tests/run.sh tests/test_lib.sh` → `0 failed`. If the nanosecond case
fails, strip the fraction in `to_epoch` (`date -u -d "${1%%.*}Z"` when `$1` contains a `.`) and
re-run.
- [ ] **Step 6:** Commit (`git add .gitattributes scripts/lib.sh tests`, then
`git update-index --chmod=+x tests/run.sh tests/stubs/docker`):
`test: unit test harness and shared script helpers (#1)`.

### Task 2: `scripts/check-age.sh`

**Interfaces — Consumes:** `manifest_get`, `days_since`, `older_than`, `trivy_built`, `warn`,
`host_path`, `docker_run`, `GRYPE_OFFLINE`. **Produces:** `check-age.sh VULNDB_DIR`: stdout one
line per database (`trivy-db       built T, 1.0 days old`) and `WARNING: <name> is <d> days old
(built T); limit N days. Import a newer release.`; exit 0 fresh or stale, 1 if missing. Honours
`GRYPE_IMAGE`.

- [ ] **Step 1: Failing tests** — `tests/test_check_age.sh`:
```bash
# Unit tests for scripts/check-age.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

check_age() { bash "$SCRIPTS/check-age.sh" "$@" 2>&1; }

test_fresh_databases_give_no_warning() {
  make_vulndb db 1 1 1
  out=$(check_age db)
  assert_contains "$out" "trivy-db"
  assert_contains "$out" "trivy-java-db"
  assert_contains "$out" "grype-db"
  assert_not_contains "$out" "WARNING"
}

test_each_stale_database_is_named_and_the_check_still_passes() {
  make_vulndb db 9 10 8
  out=$(check_age db)
  assert_contains "$out" "WARNING: trivy-db is 9.0 days old"
  assert_contains "$out" "WARNING: trivy-java-db is 10.0 days old"
  assert_contains "$out" "WARNING: grype-db is 8.0 days old"
  assert_contains "$out" "limit 7 days. Import a newer release."
}

test_a_simulated_clock_makes_fresh_databases_stale() {
  make_vulndb db 0 0 0
  AGE_CHECK_NOW=$(iso -8)
  export AGE_CHECK_NOW
  assert_contains "$(check_age db)" "WARNING: trivy-db is 8.0 days old"
}

test_the_java_index_has_its_own_limit() {
  make_vulndb db 1 20 1
  export MAX_JAVA_DB_AGE_DAYS=30
  assert_not_contains "$(check_age db)" "WARNING"
}

test_the_main_limit_does_not_cover_the_java_index() {
  make_vulndb db 10 10 10
  export MAX_DB_AGE_DAYS=30
  out=$(check_age db)
  assert_contains "$out" "WARNING: trivy-java-db"
  assert_not_contains "$out" "WARNING: trivy-db"
  assert_not_contains "$out" "WARNING: grype-db"
}

test_github_actions_gets_an_annotation() {
  make_vulndb db 9 1 1
  export GITHUB_ACTIONS=true
  assert_contains "$(check_age db)" "::warning title=Stale vulnerability database::trivy-db is 9.0 days old"
}

test_a_database_built_in_the_future_is_not_stale() {
  make_vulndb db -1 1 1
  out=$(check_age db)
  assert_contains "$out" "0.0 days old"
  assert_not_contains "$out" "WARNING"
}

test_a_missing_trivy_database_fails() {
  make_vulndb db 1 1 1
  rm db/trivy/java-db/metadata.json
  if out=$(check_age db); then fail "expected failure"; fi
  assert_contains "$out" "java-db/metadata.json not found"
}

test_a_missing_grype_database_fails() {
  make_vulndb db 1 1 1
  unset FAKE_GRYPE_BUILT
  if out=$(check_age db); then fail "expected failure"; fi
  assert_contains "$out" "grype-db not found"
}

test_nothing_imported_yet_fails_clearly() {
  mkdir db
  if out=$(check_age db); then fail "expected failure"; fi
  assert_contains "$out" "import a release first"
}

test_a_limit_that_is_not_a_number_fails() {
  make_vulndb db 1 1 1
  export MAX_DB_AGE_DAYS=seven
  if out=$(check_age db); then fail "expected failure"; fi
  assert_contains "$out" "whole numbers of days"
}

test_grype_runs_with_no_network_and_a_read_only_database() {
  make_vulndb db 1 1 1
  check_age db > /dev/null
  calls=$(cat "$FAKE_DOCKER_LOG")
  assert_contains "$calls" "--network none"
  assert_contains "$calls" "/grype:/db/grype:ro"
  assert_contains "$calls" "GRYPE_DB_AUTO_UPDATE=false"
}
```
- [ ] **Step 2:** `bash tests/run.sh tests/test_check_age.sh` → FAIL (script missing).
- [ ] **Step 3: Implement** `scripts/check-age.sh`:
```bash
#!/usr/bin/env bash
# check-age.sh VULNDB_DIR
# Prints each database's build time and age, and a WARNING for any database past its limit:
# MAX_DB_AGE_DAYS for trivy-db and grype-db, MAX_JAVA_DB_AGE_DAYS for trivy-java-db (both 7
# days by default). Exits 0 whether the databases are fresh or stale, and 1 if one is missing.
# AGE_CHECK_NOW (an ISO 8601 time) replaces the current time, for tests.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

[[ $# -eq 1 ]] || die "usage: check-age.sh VULNDB_DIR"
db=$1
max=${MAX_DB_AGE_DAYS:-7}
max_java=${MAX_JAVA_DB_AGE_DAYS:-7}
[[ $max =~ ^[0-9]+$ && $max_java =~ ^[0-9]+$ ]] \
  || die "MAX_DB_AGE_DAYS and MAX_JAVA_DB_AGE_DAYS must be whole numbers of days"
[[ -f $db/MANIFEST ]] || die "no MANIFEST in $db; import a release first"
grype_image=${GRYPE_IMAGE:-$(manifest_get "$db/MANIFEST" GRYPE_IMAGE)}

# check NAME BUILT LIMIT_DAYS
check() {
  local age
  age=$(days_since "$2")
  printf '%-14s built %s, %s days old\n' "$1" "$2" "$age"
  if older_than "$2" "$3"; then
    warn "$1 is $age days old (built $2); limit $3 days. Import a newer release."
  fi
}

trivy_db=$(trivy_built "$db/trivy/db/metadata.json")
java_db=$(trivy_built "$db/trivy/java-db/metadata.json")
status=$(docker_run --network none -v "$(host_path "$db/grype"):/db/grype:ro" "${GRYPE_OFFLINE[@]}" \
  "$grype_image" db status -o json) || die "grype-db not found in $db/grype; import a release first"
grype_db=$(sed -n 's/.*"built" *: *"\([^"]*\)".*/\1/p' <<< "$status")
[[ -n $grype_db ]] || die "grype db status gave no build time"

check trivy-db "$trivy_db" "$max"
check trivy-java-db "$java_db" "$max_java"
check grype-db "$grype_db" "$max"
```
- [ ] **Step 4:** `bash tests/run.sh` → `0 failed`.
- [ ] **Step 5:** Commit (`git update-index --chmod=+x scripts/check-age.sh`):
`feat: check-age.sh warns when a database is past its limit (#1)`.

### Task 3: `scripts/package.sh`

**Interfaces — Consumes:** `WORK_DIR/fetch.env` (keys `TRIVY_VERSION TRIVY_SOURCE TRIVY_IMAGE
GRYPE_VERSION GRYPE_SOURCE GRYPE_IMAGE TRIVY_DB_BUILT TRIVY_JAVA_DB_BUILT GRYPE_DB_BUILT`),
`WORK_DIR/trivy/{db,java-db}`, `WORK_DIR/grype-db.tar.zst`. **Produces:** stdout = the release
path `OUT_DIR/scanners-YYYY-MM-DD`; files `images/trivy-<v>.tar.gz`, `images/grype-<v>.tar.gz`,
`db/trivy-db.tar.gz` (top dir `db/`), `db/trivy-java-db.tar.gz` (top dir `java-db/`),
`db/grype-db.tar.zst`, `MANIFEST` (`RELEASE`, `CREATED`, then fetch.env), `SHA256SUMS`.

- [ ] **Step 1: Failing tests** — `tests/test_package.sh`:
```bash
# Unit tests for scripts/package.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

package() { bash "$SCRIPTS/package.sh" "$@"; }

test_packages_a_dated_release_and_prints_its_path() {
  make_work work
  release=$(package work out 2> /dev/null)
  assert_eq "$release" "out/scanners-$(date -u +%Y-%m-%d)"
  for f in images/trivy-0.75.0.tar.gz images/grype-0.120.1.tar.gz db/trivy-db.tar.gz \
           db/trivy-java-db.tar.gz db/grype-db.tar.zst MANIFEST SHA256SUMS; do
    [[ -f $release/$f ]] || fail "missing $f"
  done
}

test_the_manifest_records_versions_digests_and_build_times() {
  make_work work
  release=$(package work out 2> /dev/null)
  manifest=$(cat "$release/MANIFEST")
  assert_contains "$manifest" "RELEASE=scanners-$(date -u +%Y-%m-%d)"
  assert_contains "$manifest" "CREATED="
  assert_contains "$manifest" "TRIVY_SOURCE=ghcr.io/aquasecurity/trivy@sha256:"
  assert_contains "$manifest" "GRYPE_IMAGE=airgap-vuln-scan/grype:0.120.1"
  assert_contains "$manifest" "TRIVY_JAVA_DB_BUILT="
}

test_the_checksums_cover_every_file() {
  make_work work
  release=$(package work out 2> /dev/null)
  (cd "$release" && sha256sum -c --strict --quiet SHA256SUMS) || fail "SHA256SUMS doesn't verify"
  assert_eq "$(wc -l < "$release/SHA256SUMS" | tr -d ' ')" 6
}

test_the_database_archives_hold_db_and_java_db() {
  make_work work
  release=$(package work out 2> /dev/null)
  assert_contains "$(tar -tzf "$release/db/trivy-db.tar.gz")" "db/metadata.json"
  assert_contains "$(tar -tzf "$release/db/trivy-java-db.tar.gz")" "java-db/metadata.json"
}

test_saves_both_images() {
  make_work work
  package work out > /dev/null 2>&1
  calls=$(cat "$FAKE_DOCKER_LOG")
  assert_contains "$calls" "save airgap-vuln-scan/trivy:0.75.0"
  assert_contains "$calls" "save airgap-vuln-scan/grype:0.120.1"
}

test_a_rerun_on_the_same_day_replaces_the_release() {
  make_work work
  release=$(package work out 2> /dev/null)
  touch "$release/stray"
  package work out > /dev/null 2>&1
  [[ ! -e $release/stray ]] || fail "the old release wasn't replaced"
}

test_fails_without_fetch_output() {
  mkdir work
  if out=$(package work out 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "run fetch.sh first"
}
```
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** `scripts/package.sh`:
```bash
#!/usr/bin/env bash
# package.sh WORK_DIR OUT_DIR
# Connected side. Packages what fetch.sh left in WORK_DIR as OUT_DIR/scanners-YYYY-MM-DD/ (the
# UTC date; a re-run on the same day replaces it), and prints that path.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

[[ $# -eq 2 ]] || die "usage: package.sh WORK_DIR OUT_DIR"
work=$1 out=$2
[[ -f $work/fetch.env ]] || die "no fetch.env in $work; run fetch.sh first"

trivy_image=$(manifest_get "$work/fetch.env" TRIVY_IMAGE)
trivy_version=$(manifest_get "$work/fetch.env" TRIVY_VERSION)
grype_image=$(manifest_get "$work/fetch.env" GRYPE_IMAGE)
grype_version=$(manifest_get "$work/fetch.env" GRYPE_VERSION)

name=scanners-$(date -u +%Y-%m-%d)
release=$out/$name
rm -rf "$release"
mkdir -p "$release/images" "$release/db"

log "Saving the scanner images"
docker save "$trivy_image" | gzip > "$release/images/trivy-$trivy_version.tar.gz"
docker save "$grype_image" | gzip > "$release/images/grype-$grype_version.tar.gz"

log "Packing the databases"
tar -czf "$release/db/trivy-db.tar.gz" -C "$work/trivy" db
tar -czf "$release/db/trivy-java-db.tar.gz" -C "$work/trivy" java-db
cp "$work/grype-db.tar.zst" "$release/db/grype-db.tar.zst"

{
  printf 'RELEASE=%s\n' "$name"
  printf 'CREATED=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat "$work/fetch.env"
} > "$release/MANIFEST"

(cd "$release" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
  | xargs sha256sum > SHA256SUMS)
log "Packaged $release ($(du -sh "$release" | cut -f1))"
printf '%s\n' "$release"
```
- [ ] **Step 4:** `bash tests/run.sh` → `0 failed`.
- [ ] **Step 5:** Commit (+x on `scripts/package.sh`): `feat: package.sh builds a dated, checksummed release (#1)`.

### Task 4: `scripts/import.sh`

**Interfaces — Consumes:** a release from Task 3; `manifest_get` with patterns; `GRYPE_OFFLINE`.
**Produces:** `import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]` → `VULNDB_ROOT/current/{MANIFEST,trivy/db,trivy/java-db,grype}`, previous kept in `VULNDB_ROOT/previous/`; pushes
`PREFIX/{trivy,grype}:{<v>,latest}`. Failure messages: `<file>: FAILED` (from sha256sum),
`checksum verification failed; nothing was loaded`, `SHA256SUMS doesn't cover <file>; nothing was loaded`.

- [ ] **Step 1: Failing tests** — `tests/test_import.sh`:
```bash
# Unit tests for scripts/import.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

import() { bash "$SCRIPTS/import.sh" "$@"; }

# release [DIR]: package a release from fake fetch output under DIR (default .); print its path.
release() {
  make_work "${1:-.}/work"
  bash "$SCRIPTS/package.sh" "${1:-.}/work" "${1:-.}/out" 2> /dev/null
}

# resum RELEASE: rewrite SHA256SUMS after a test changes a file on purpose.
resum() { (cd "$1" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS); }

test_imports_a_release_into_current() {
  r=$(release)
  import "$r" root 2> /dev/null
  for f in MANIFEST trivy/db/metadata.json trivy/java-db/metadata.json; do
    [[ -f root/current/$f ]] || fail "current/ has no $f"
  done
  [[ -d root/current/grype && ! -e root/incoming ]] || fail "grype/ missing or incoming/ left behind"
  calls=$(cat "$FAKE_DOCKER_LOG")
  assert_contains "$calls" "load -q -i $r/images/trivy-0.75.0.tar.gz"
  assert_contains "$calls" "load -q -i $r/images/grype-0.120.1.tar.gz"
  assert_contains "$calls" "--network none"
  assert_contains "$calls" "db import /release/grype-db.tar.zst"
}

test_a_second_import_keeps_the_first_as_previous() {
  r=$(release)
  import "$r" root 2> /dev/null
  touch root/current/first
  import "$r" root 2> /dev/null
  [[ -f root/previous/first ]] || fail "previous/ isn't the first import"
  [[ ! -e root/current/first ]] || fail "current/ wasn't replaced"
}

test_a_changed_file_is_refused_before_anything_is_loaded() {
  r=$(release)
  import "$r" root 2> /dev/null
  before=$(cat root/current/MANIFEST)
  : > "$FAKE_DOCKER_LOG"
  printf 'x' >> "$r/db/grype-db.tar.zst"
  if out=$(import "$r" root 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "db/grype-db.tar.zst: FAILED"
  assert_contains "$out" "nothing was loaded"
  assert_eq "$(cat "$FAKE_DOCKER_LOG")" ""
  assert_eq "$(cat root/current/MANIFEST)" "$before"
}

test_a_missing_file_is_refused() {
  r=$(release)
  rm "$r/db/trivy-java-db.tar.gz"
  if out=$(import "$r" root 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "nothing was loaded"
  [[ ! -e root/current ]] || fail "current/ was created"
}

test_the_checksums_must_cover_the_manifest() {
  r=$(release)
  sed -i '/ MANIFEST$/d' "$r/SHA256SUMS"
  if out=$(import "$r" root 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "SHA256SUMS doesn't cover MANIFEST"
}

test_binary_mode_checksums_are_accepted() {
  r=$(release)
  sed -i 's/  / */' "$r/SHA256SUMS"
  import "$r" root 2> /dev/null
  [[ -f root/current/MANIFEST ]] || fail "not imported"
}

test_a_manifest_value_that_could_escape_the_release_is_refused() {
  r=$(release)
  sed -i 's|^TRIVY_VERSION=.*|TRIVY_VERSION=../../x|' "$r/MANIFEST"
  resum "$r"
  if out=$(import "$r" root 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "unexpected TRIVY_VERSION"
}

test_a_broken_archive_leaves_current_untouched() {
  r=$(release)
  import "$r" root 2> /dev/null
  before=$(cat root/current/MANIFEST)
  printf 'not a tar' > "$r/db/trivy-java-db.tar.gz"
  resum "$r"
  if import "$r" root > /dev/null 2>&1; then fail "expected failure"; fi
  assert_eq "$(cat root/current/MANIFEST)" "$before"
  [[ -f root/current/trivy/java-db/metadata.json ]] || fail "current/ was damaged"
}

test_paths_with_spaces_work() {
  mkdir "a b"
  r=$(release "a b")
  import "$r" "a b/root" 2> /dev/null
  [[ -f "a b/root/current/MANIFEST" ]] || fail "not imported"
}

test_pushes_to_a_registry_when_asked() {
  r=$(release)
  import "$r" root --registry registry.internal/scanners 2> /dev/null
  calls=$(cat "$FAKE_DOCKER_LOG")
  for ref in trivy:0.75.0 trivy:latest grype:0.120.1 grype:latest; do
    assert_contains "$calls" "push -q registry.internal/scanners/$ref"
  done
}

test_not_a_release_directory() {
  mkdir empty
  if out=$(import empty root 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "no SHA256SUMS in empty"
}
```
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** `scripts/import.sh`:
```bash
#!/usr/bin/env bash
# import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]
# Both forges. Verifies every file in the release against SHA256SUMS before loading anything,
# loads the scanner images (and pushes them to PREFIX if given), then unpacks the databases into
# VULNDB_ROOT/incoming and swaps that in as VULNDB_ROOT/current, keeping the old one as
# VULNDB_ROOT/previous. A failure before the swap leaves current/ untouched.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

usage() { die "usage: import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]"; }
[[ $# -eq 2 || $# -eq 4 ]] || usage
release=$1 root=$2 registry=""
if [[ $# -eq 4 ]]; then
  [[ $3 == --registry && -n $4 ]] || usage
  registry=$4
fi
[[ -f $release/SHA256SUMS ]] || die "no SHA256SUMS in $release; is it a release directory?"

# covered FILE: stop unless SHA256SUMS lists FILE (with or without a binary-mode '*').
covered() {
  awk '{ sub(/^\*/, "", $2); print $2 }' "$release/SHA256SUMS" | grep -Fxq "$1" \
    || die "SHA256SUMS doesn't cover $1; nothing was loaded"
}

log "Verifying $release"
(cd "$release" && sha256sum -c --strict --quiet SHA256SUMS) \
  || die "checksum verification failed; nothing was loaded"
covered MANIFEST

manifest=$release/MANIFEST
version='^[0-9A-Za-z._-]+$'
name=$(manifest_get "$manifest" RELEASE '^scanners-[0-9]{4}-[0-9]{2}-[0-9]{2}$')
trivy_version=$(manifest_get "$manifest" TRIVY_VERSION "$version")
grype_version=$(manifest_get "$manifest" GRYPE_VERSION "$version")
trivy_image=$(manifest_get "$manifest" TRIVY_IMAGE '^airgap-vuln-scan/trivy:[0-9A-Za-z._-]+$')
grype_image=$(manifest_get "$manifest" GRYPE_IMAGE '^airgap-vuln-scan/grype:[0-9A-Za-z._-]+$')
trivy_tar=images/trivy-$trivy_version.tar.gz
grype_tar=images/grype-$grype_version.tar.gz
for f in "$trivy_tar" "$grype_tar" db/trivy-db.tar.gz db/trivy-java-db.tar.gz db/grype-db.tar.zst; do
  covered "$f"
done

log "Loading the scanner images"
docker load -q -i "$release/$trivy_tar"
docker load -q -i "$release/$grype_tar"
docker image inspect "$trivy_image" "$grype_image" > /dev/null \
  || die "the image archives don't hold $trivy_image and $grype_image"

# push_as IMAGE NAME: tag IMAGE as PREFIX/NAME and push it.
push_as() {
  docker tag "$1" "$registry/$2"
  docker push -q "$registry/$2"
}
if [[ -n $registry ]]; then
  log "Pushing to $registry"
  push_as "$trivy_image" "trivy:$trivy_version"
  push_as "$trivy_image" trivy:latest
  push_as "$grype_image" "grype:$grype_version"
  push_as "$grype_image" grype:latest
fi

log "Unpacking the databases"
incoming=$root/incoming
rm -rf "$incoming"
mkdir -p "$incoming/trivy" "$incoming/grype"
tar -xzf "$release/db/trivy-db.tar.gz" -C "$incoming/trivy"
tar -xzf "$release/db/trivy-java-db.tar.gz" -C "$incoming/trivy"
[[ -f $incoming/trivy/db/metadata.json && -f $incoming/trivy/java-db/metadata.json ]] \
  || die "the Trivy archives don't hold db/ and java-db/"
docker_run --network none -v "$(host_path "$incoming/grype"):/db/grype" \
  -v "$(host_path "$release/db"):/release:ro" "${GRYPE_OFFLINE[@]}" \
  "$grype_image" db import /release/grype-db.tar.zst
cp "$manifest" "$incoming/MANIFEST"

rm -rf "$root/previous"
if [[ -d $root/current ]]; then mv "$root/current" "$root/previous"; fi
mv "$incoming" "$root/current"
log "Imported $name into $root/current"
```
- [ ] **Step 4:** `bash tests/run.sh` → `0 failed`.
- [ ] **Step 5:** Commit (+x): `feat: import.sh verifies, loads and swaps in a release (#1)`.

### Task 5: `scripts/scan.sh`

**Interfaces — Consumes:** `check-age.sh` (Task 2), `TRIVY_OFFLINE`, `GRYPE_OFFLINE`,
`manifest_get`, `host_path`, `docker_run`. **Produces:** `scan.sh VULNDB_DIR IMAGE_TAR
[REPORTS_DIR]`; `REPORTS_DIR/{trivy,grype}.json`; honours `TRIVY_IMAGE`, `GRYPE_IMAGE`.

- [ ] **Step 1: Failing tests** — `tests/test_scan.sh`:
```bash
# Unit tests for scripts/scan.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

scan() { bash "$SCRIPTS/scan.sh" "$@" 2>&1; }

test_checks_age_then_runs_both_scanners_offline() {
  make_vulndb db 9 1 1
  touch image.tar
  out=$(scan db image.tar reports)
  assert_contains "$out" "WARNING: trivy-db is 9.0 days old"
  calls=$(cat "$FAKE_DOCKER_LOG")
  assert_contains "$calls" "airgap-vuln-scan/trivy:0.75.0 image --input /scan/image.tar"
  assert_contains "$calls" "--skip-db-update --skip-java-db-update --skip-check-update --offline-scan --skip-version-check --disable-telemetry"
  assert_contains "$calls" "--cache-backend memory"
  assert_contains "$calls" "airgap-vuln-scan/grype:0.120.1 docker-archive:/scan/image.tar"
  assert_contains "$calls" "GRYPE_DB_AUTO_UPDATE=false"
  assert_contains "$calls" ":/db:ro"
  assert_eq "$(grep -c '^run ' "$FAKE_DOCKER_LOG")" "$(grep -c '^run .*--network none' "$FAKE_DOCKER_LOG")"
  [[ -d reports ]] || fail "reports/ wasn't created"
}

test_image_overrides_are_used() {
  make_vulndb db 1 1 1
  touch image.tar
  export TRIVY_IMAGE=registry.internal/scanners/trivy:0.75.0 GRYPE_IMAGE=registry.internal/scanners/grype:0.120.1
  scan db image.tar > /dev/null
  calls=$(cat "$FAKE_DOCKER_LOG")
  assert_contains "$calls" "registry.internal/scanners/trivy:0.75.0 image"
  assert_contains "$calls" "registry.internal/scanners/grype:0.120.1 docker-archive:"
}

test_a_missing_image_fails() {
  make_vulndb db 1 1 1
  if out=$(scan db missing.tar); then fail "expected failure"; fi
  assert_contains "$out" "missing.tar not found"
}

test_nothing_imported_yet_fails_clearly() {
  mkdir db; touch image.tar
  if out=$(scan db image.tar); then fail "expected failure"; fi
  assert_contains "$out" "import a release first"
}
```
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** `scripts/scan.sh`:
```bash
#!/usr/bin/env bash
# scan.sh VULNDB_DIR IMAGE_TAR [REPORTS_DIR]
# Both forges. Checks the databases' age, then scans IMAGE_TAR (from `docker save`) with Trivy
# and Grype, each with no network and the databases mounted read-only. Tables go to stdout and
# JSON reports to REPORTS_DIR (default ./reports). Findings don't fail the scan.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

[[ $# -eq 2 || $# -eq 3 ]] || die "usage: scan.sh VULNDB_DIR IMAGE_TAR [REPORTS_DIR]"
db=$1 image_tar=$2 reports=${3:-reports}
[[ -f $image_tar ]] || die "$image_tar not found"
bash "$(dirname "$0")/check-age.sh" "$db"

trivy_image=${TRIVY_IMAGE:-$(manifest_get "$db/MANIFEST" TRIVY_IMAGE)}
grype_image=${GRYPE_IMAGE:-$(manifest_get "$db/MANIFEST" GRYPE_IMAGE)}
mkdir -p "$reports"
mounts=(-v "$(host_path "$db"):/db:ro" -v "$(host_path "$image_tar"):/scan/image.tar:ro"
  -v "$(host_path "$reports"):/reports")

log "Trivy ($trivy_image)"
docker_run --network none "${mounts[@]}" "$trivy_image" image --input /scan/image.tar \
  "${TRIVY_OFFLINE[@]}" --cache-backend memory --scanners vuln --no-progress \
  --format json --output /reports/trivy.json
docker_run --network none "${mounts[@]}" "$trivy_image" convert --format table /reports/trivy.json

log "Grype ($grype_image)"
docker_run --network none "${mounts[@]}" "${GRYPE_OFFLINE[@]}" "$grype_image" \
  docker-archive:/scan/image.tar -o table -o json=/reports/grype.json

log "Reports in $reports"
```
- [ ] **Step 4:** `bash tests/run.sh` → `0 failed`.
- [ ] **Step 5:** Commit (+x): `feat: scan.sh runs both scanners with no network (#1)`.

### Task 6: `scripts/fetch.sh`

Its pulls and downloads are proven end to end in CI (Task 7); unit tests cover arguments only.

**Interfaces — Produces:** `fetch.sh WORK_DIR [--java-db-refresh-days N]` → `WORK_DIR/trivy/{db,java-db}`, `WORK_DIR/grype-db.tar.zst`, `WORK_DIR/fetch.env` (keys as Task 3 consumes); log line `Reusing Trivy's Java database` when not due. Env `TRIVY_IMAGE_REF`, `GRYPE_IMAGE_REF`.

- [ ] **Step 1: Failing tests** — `tests/test_fetch.sh`:
```bash
# Unit tests for scripts/fetch.sh. Its pulls and downloads are tested end to end in CI.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

test_requires_a_work_dir() {
  if out=$(bash "$SCRIPTS/fetch.sh" 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "usage: fetch.sh WORK_DIR"
}

test_rejects_a_refresh_interval_that_is_not_a_number() {
  if out=$(bash "$SCRIPTS/fetch.sh" work --java-db-refresh-days soon 2>&1); then fail "expected failure"; fi
  assert_contains "$out" "usage: fetch.sh"
  assert_eq "$(cat "$FAKE_DOCKER_LOG")" ""
}
```
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implement** `scripts/fetch.sh`:
```bash
#!/usr/bin/env bash
# fetch.sh WORK_DIR [--java-db-refresh-days N]
# Connected side. Pulls the latest official Trivy and Grype images, pins each by digest and
# tags it airgap-vuln-scan/<tool>:<version>, then downloads the databases into WORK_DIR:
# Trivy's into WORK_DIR/trivy, Grype's archive to WORK_DIR/grype-db.tar.zst. Trivy's Java
# index is downloaded again only once it's more than N days old (default 0: every time).
# Writes WORK_DIR/fetch.env for package.sh.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

TRIVY_IMAGE_REF=${TRIVY_IMAGE_REF:-ghcr.io/aquasecurity/trivy:latest}
GRYPE_IMAGE_REF=${GRYPE_IMAGE_REF:-ghcr.io/anchore/grype:latest}

usage() { die "usage: fetch.sh WORK_DIR [--java-db-refresh-days N]"; }
[[ $# -eq 1 || $# -eq 3 ]] || usage
work=$1 refresh_days=0
if [[ $# -eq 3 ]]; then
  [[ $2 == --java-db-refresh-days && $3 =~ ^[0-9]+$ ]] || usage
  refresh_days=$3
fi
mkdir -p "$work/trivy"
cache=$(host_path "$work/trivy")

# pin REF TOOL VERSION_COMMAND: pull REF and tag it airgap-vuln-scan/TOOL:VERSION. Prints
# "SOURCE IMAGE VERSION", where SOURCE is REF pinned by digest.
pin() {
  local source version
  docker pull -q "$1" > /dev/null
  source=$(docker image inspect --format '{{index .RepoDigests 0}}' "$1")
  version=$(docker_run "$source" "$3" | sed -n 's/^Version: *v\{0,1\}//p' | head -n 1)
  [[ $version =~ ^[0-9A-Za-z._-]+$ ]] || die "couldn't read $2's version from $source"
  docker tag "$source" "airgap-vuln-scan/$2:$version"
  printf '%s %s %s\n' "$source" "airgap-vuln-scan/$2:$version" "$version"
}

log "Pulling $TRIVY_IMAGE_REF and $GRYPE_IMAGE_REF"
pinned=$(pin "$TRIVY_IMAGE_REF" trivy --version)
read -r trivy_source trivy_image trivy_version <<< "$pinned"
pinned=$(pin "$GRYPE_IMAGE_REF" grype version)
read -r grype_source grype_image grype_version <<< "$pinned"

trivy_args=(--cache-dir /cache --skip-version-check --disable-telemetry --no-progress)
log "Downloading Trivy's database"
docker_run -v "$cache:/cache" "$trivy_image" image --download-db-only "${trivy_args[@]}"

java_meta=$work/trivy/java-db/metadata.json
if (( refresh_days > 0 )) && [[ -f $java_meta ]] && ! older_than "$(trivy_built "$java_meta")" "$refresh_days"; then
  log "Reusing Trivy's Java database (built $(trivy_built "$java_meta")); it's downloaded again after $refresh_days days"
else
  log "Downloading Trivy's Java database"
  docker_run -v "$cache:/cache" "$trivy_image" image --download-java-db-only "${trivy_args[@]}"
fi

log "Downloading Grype's database"
listing=$(docker_run "$grype_image" db list)
url=$(sed -n 's/^DB URL: *//p' <<< "$listing")
checksum=$(sed -n 's/^Checksum: *sha256://p' <<< "$listing")
grype_built=$(docker_run "$grype_image" db list -o json | sed -n 's/.*"built" *: *"\([^"]*\)".*/\1/p')
[[ $url == https://* && $checksum =~ ^[0-9a-f]{64}$ && -n $grype_built ]] \
  || die "couldn't read Grype's database listing"
curl -fsSL --retry 3 -o "$work/grype-db.tar.zst.part" "$url"
actual=$(sha256sum "$work/grype-db.tar.zst.part" | cut -d ' ' -f 1)
[[ $actual == "$checksum" ]] || die "Grype's database doesn't match its listing (sha256 $actual, expected $checksum)"
mv "$work/grype-db.tar.zst.part" "$work/grype-db.tar.zst"

trivy_db_built=$(trivy_built "$work/trivy/db/metadata.json")
java_db_built=$(trivy_built "$java_meta")
cat > "$work/fetch.env" <<EOF
TRIVY_VERSION=$trivy_version
TRIVY_SOURCE=$trivy_source
TRIVY_IMAGE=$trivy_image
GRYPE_VERSION=$grype_version
GRYPE_SOURCE=$grype_source
GRYPE_IMAGE=$grype_image
TRIVY_DB_BUILT=$trivy_db_built
TRIVY_JAVA_DB_BUILT=$java_db_built
GRYPE_DB_BUILT=$grype_built
EOF
log "Fetched Trivy $trivy_version and Grype $grype_version, with their databases, into $work"
```
- [ ] **Step 4:** `bash tests/run.sh` → `0 failed`.
- [ ] **Step 5:** Commit (+x): `feat: fetch.sh pulls the scanners and downloads their databases (#1)`.

### Task 7: CI workflow, push, PR, green run

**Files:** Create `.github/workflows/demo.yml`.

- [ ] **Step 1: Write** `.github/workflows/demo.yml`:
```yaml
# Proves issue #1's acceptance criteria end to end. One job plays both forges: the connected
# one fetches, packages and imports a release; the disconnected one imports the same release
# into a registry and a database directory, then scans with no network. Runs daily after
# Grype's 06:00 UTC database, on pull requests, on pushes to main, and by hand. Scheduled and
# manual runs keep the day's release as an artifact for 7 days.
name: demo

on:
  schedule:
    - cron: "0 7 * * *"
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

env:
  # An official Tomcat image from 2021: OS packages and JARs, so both scanners find something
  # and Trivy needs its Java index.
  EXAMPLE_IMAGE: tomcat:9.0.50-jdk11-openjdk-slim@sha256:0c561f02b73699d076011412ec3d95359402fcbf382cbb750d12ed51635faaf2
  SHELLCHECK_IMAGE: koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d
  REGISTRY_IMAGE: registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8
  W: /mnt/airgap # the runner's larger disk: the Java index unpacks to several GB, three times

jobs:
  demo:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Unit tests
        run: bash tests/run.sh

      - name: shellcheck
        run: >-
          docker run --rm -v "$PWD:/repo" -w /repo "$SHELLCHECK_IMAGE" -x -P SCRIPTDIR
          scripts/*.sh tests/*.sh tests/stubs/docker

      - name: Work space
        run: |
          sudo mkdir -p "$W"
          sudo chown "$(id -u):$(id -g)" "$W"
          df -h / /mnt

      - name: The image under test
        run: |
          docker pull -q "$EXAMPLE_IMAGE"
          docker tag "$EXAMPLE_IMAGE" example:under-test
          docker save example:under-test -o "$W/example.tar"

      - name: "Connected: fetch"
        run: scripts/fetch.sh "$W/fetch"

      - name: "Connected: package"
        run: |
          release=$(scripts/package.sh "$W/fetch" "$W/releases")
          echo "RELEASE=$release" >> "$GITHUB_ENV"
          echo "RELEASE_NAME=$(basename "$release")" >> "$GITHUB_ENV"
          cat "$release/MANIFEST"

      - name: "Connected: import and scan"
        run: |
          scripts/import.sh "$RELEASE" "$W/connected"
          scripts/scan.sh "$W/connected/current" "$W/example.tar" "$W/reports/connected"

      - name: Keep the release (7 days)
        if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: ${{ env.RELEASE_NAME }}
          path: ${{ env.RELEASE }}
          retention-days: 7
          compression-level: 0

      - name: "Disconnected: a registry to load into"
        run: docker run -d --name registry -p 5000:5000 "$REGISTRY_IMAGE"

      - name: "Disconnected: import"
        run: scripts/import.sh "$RELEASE" "$W/disconnected" --registry localhost:5000/scanners

      - name: "Disconnected: the scan containers have no network"
        run: |
          trivy_image=$(sed -n 's/^TRIVY_IMAGE=//p' "$W/disconnected/current/MANIFEST")
          if docker run --rm --network none --entrypoint wget "$trivy_image" -q -T 5 -O /dev/null https://mirror.gcr.io; then
            echo "::error::a --network none container reached the internet"
            exit 1
          fi

      - name: "Disconnected: scan with fresh databases"
        run: |
          scripts/scan.sh "$W/disconnected/current" "$W/example.tar" "$W/reports/disconnected" 2>&1 | tee "$W/scan-fresh.log"
          if grep -q '^WARNING:' "$W/scan-fresh.log"; then
            echo "::error::fresh databases gave a warning"
            exit 1
          fi

      - name: "Disconnected: databases over 7 days old warn, and the scan still passes"
        run: |
          AGE_CHECK_NOW=$(date -u -d '+8 days' +%Y-%m-%dT%H:%M:%SZ) \
            scripts/scan.sh "$W/disconnected/current" "$W/example.tar" "$W/reports/stale" 2>&1 | tee "$W/scan-stale.log"
          for db in trivy-db trivy-java-db grype-db; do
            grep -q "^WARNING: $db is " "$W/scan-stale.log" || { echo "::error::no warning for $db"; exit 1; }
          done

      - name: "Disconnected: a changed file is refused"
        run: |
          cp -al "$RELEASE" "$W/tampered"
          cp --remove-destination "$RELEASE/db/grype-db.tar.zst" "$W/tampered/db/grype-db.tar.zst"
          printf 'x' | dd of="$W/tampered/db/grype-db.tar.zst" bs=1 seek=1000 conv=notrunc status=none
          before=$(cat "$W/disconnected/current/MANIFEST")
          if scripts/import.sh "$W/tampered" "$W/disconnected" > "$W/tamper.log" 2>&1; then
            cat "$W/tamper.log"
            echo "::error::a changed release was imported"
            exit 1
          fi
          cat "$W/tamper.log"
          grep -q 'db/grype-db.tar.zst: FAILED' "$W/tamper.log"
          [ "$before" = "$(cat "$W/disconnected/current/MANIFEST")" ]

      - name: "Connected: the Java index is reused until it's due"
        run: |
          scripts/fetch.sh "$W/fetch" --java-db-refresh-days 30 2>&1 | tee "$W/refetch.log"
          grep -q "Reusing Trivy's Java database" "$W/refetch.log"

      - name: Keep the reports (7 days)
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: reports
          path: /mnt/airgap/reports
          retention-days: 7
          if-no-files-found: ignore
```
- [ ] **Step 2:** If Docker Desktop is running: `MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/repo -w /repo rhysd/actionlint:latest -color=false`; otherwise CI is the first check.
- [ ] **Step 3:** `bash tests/run.sh` → `0 failed`. Commit (+x on scripts confirmed with `git ls-files -s scripts tests | grep 100755`): `ci: prove the acceptance criteria end to end (#1)`.
- [ ] **Step 4:** `git push -u origin feat/issue-1-offline-scan`, then open a **draft** PR
(this plan's approval is the go-ahead for this push and draft PR):
```bash
gh pr create --draft --title "feat: offline Trivy and Grype scanning with carried databases" --body-file - <<'EOF'
Closes #1.

Scan container images with Trivy and Grype where there's no internet. A daily pipeline on the
connected forge pulls the latest official images (pinned by digest), downloads their databases,
and packages a dated release with a MANIFEST and SHA256SUMS. Import verifies every checksum
before loading anything, loads and pushes the images, and swaps the databases into a directory
the runners mount read-only. Scans run with no network and warn, without failing, when a
database is more than 7 days old.

- Design: docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md, docs/architecture.md, ADR-0001
- Scripts: scripts/{fetch,package,import,check-age,scan}.sh, unit tested with a fake docker
- Proof: .github/workflows/demo.yml runs both forges end to end; each acceptance criterion is a named step

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
```
- [ ] **Step 5:** Watch the run (`gh run watch`). On a failure: read the log
(`gh run view --log-failed`), fix with superpowers:systematic-debugging, add a unit test when
the cause is in a script, commit, push. Known fallbacks: if a scanner can't read the read-only
mount, `scan.sh` copies `VULNDB_DIR` to `mktemp -d` and mounts the copy; if `/mnt` is missing,
use `$RUNNER_TEMP`; if Grype rejects `docker-archive:`, use `oci-archive:`.

### Task 8: README walkthrough and Result, from the green run

**Files:** Modify `README.md`, `docs/architecture.md` (Sizes and timing).

- [ ] **Step 1:** From the green run collect: release size (`Packaged … (1.4G)` log line),
step durations (`gh run view <id> --json jobs --jq '.jobs[0].steps[] | [.name, .startedAt, .completedAt]'`),
the warning lines from the stale step, the tamper step's `FAILED` line, and a finding count
per scanner (from the scan logs).
- [ ] **Step 2:** README: remove the "Status: design" note; add **Using it** (the commands
below) and **Gating on findings**; replace Result with the measured evidence and a link to the
run.
```markdown
## Using it

The scripts need bash, coreutils, curl, tar, gzip and Docker. Carry this repository across
once, like any other tool.

On the connected forge, once a day:

    scripts/fetch.sh work                          # pull the images, download the databases
    release=$(scripts/package.sh work releases)    # releases/scanners-YYYY-MM-DD
    scripts/import.sh "$release" /srv/vulndb       # the connected forge scans with it too

Carry `releases/scanners-YYYY-MM-DD/` across on removable media. On the disconnected forge:

    scripts/import.sh /media/scanners-YYYY-MM-DD /srv/vulndb --registry registry.internal/scanners
    docker save my-app:1.2 -o my-app.tar
    scripts/scan.sh /srv/vulndb/current my-app.tar reports

| Setting | Default | |
|---|---|---|
| `MAX_DB_AGE_DAYS` | 7 | warn when trivy-db or grype-db is older |
| `MAX_JAVA_DB_AGE_DAYS` | 7 | warn when Trivy's Java index is older; raise it if you refresh the index less often |
| `fetch.sh --java-db-refresh-days N` | 0 | download the Java index again only once it's N days old |
| `TRIVY_IMAGE_REF`, `GRYPE_IMAGE_REF` | `ghcr.io/aquasecurity/trivy:latest`, `ghcr.io/anchore/grype:latest` | what fetch pulls |
| `TRIVY_IMAGE`, `GRYPE_IMAGE` | from `MANIFEST` | what scan runs, e.g. from your registry |

## Gating on findings

`scan.sh` reports and never fails on findings. To fail a pipeline, run a scanner with its gate,
e.g. Trivy's `--exit-code 1 --severity CRITICAL` or Grype's `--fail-on critical`.
```
- [ ] **Step 3:** architecture.md "Sizes and timing": the measured size and the duration of
fetch, package, import and scan.
- [ ] **Step 4:** Commit `docs: walkthrough and results from CI (#1)`; push; confirm the run
is green; mark the PR ready (`gh pr ready`). Merging stays with the user.
- [ ] **Step 5:** Update the Obsidian handoff (Status: PR open and green; Next: user merges,
deletes `docs/issue-1-spec`; session log) and the `airgap-vuln-scan-project` memory. Don't tick
`to-do.md`.

## Verification (end to end)

- `bash tests/run.sh` → `0 failed` on the PC (Git Bash) and in CI.
- shellcheck clean in CI.
- The demo workflow green on the PR: each acceptance criterion is a named step (fresh scan with
  no network, stale warning with a pass, tamper refused, Java reuse, registry push).
- `git ls-files -s scripts tests/run.sh tests/stubs/docker` shows mode `100755`.
- README walkthrough commands match the workflow's.
- Optional, offered at the end: a whole-branch review by a fresh reviewer (the user's call; no
  subagent unless asked).
