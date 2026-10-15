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
  out=$(check_age db)
  assert_contains "$out" "20.0 days old"
  assert_not_contains "$out" "WARNING"
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
