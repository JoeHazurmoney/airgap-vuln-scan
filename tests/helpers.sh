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
