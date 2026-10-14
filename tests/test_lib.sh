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

test_docker_run_gives_containers_a_writable_tmp() {
  # Grype's image is FROM scratch with a root-owned /tmp, and containers run as the host user.
  lib docker_run some/image > /dev/null
  assert_contains "$(cat "$FAKE_DOCKER_LOG")" "--tmpfs /tmp"
}

test_host_path_gives_an_absolute_path_for_dirs_and_files() {
  mkdir "d d"; touch "d d/f"
  dir=$(lib host_path "d d")
  [[ $dir == /* || $dir == [A-Za-z]:/* ]] || fail "not absolute: $dir"
  assert_eq "$(lib host_path "d d/f")" "$dir/f"
}
