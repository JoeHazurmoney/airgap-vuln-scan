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
