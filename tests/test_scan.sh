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
