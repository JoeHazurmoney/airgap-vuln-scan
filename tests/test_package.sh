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
