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
# the runner, with a private writable /tmp: Grype's image is FROM scratch and its /tmp belongs
# to root, and without an explicit mode Docker copies that mode onto the tmpfs.
# MSYS_NO_PATHCONV stops Git Bash rewriting the container-side paths.
docker_run() {
  MSYS_NO_PATHCONV=1 docker run --rm --user "$(id -u):$(id -g)" --tmpfs /tmp:mode=1777 \
    -e HOME=/tmp "$@"
}

# The settings that keep each scanner offline, with its databases mounted at /db. Used by the
# scripts that source this file.
# shellcheck disable=SC2034
TRIVY_OFFLINE=(--cache-dir /db/trivy --skip-db-update --skip-java-db-update --skip-check-update
  --offline-scan --skip-version-check --disable-telemetry)
# shellcheck disable=SC2034
GRYPE_OFFLINE=(-e GRYPE_DB_CACHE_DIR=/db/grype -e GRYPE_DB_AUTO_UPDATE=false
  -e GRYPE_DB_VALIDATE_AGE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false)
