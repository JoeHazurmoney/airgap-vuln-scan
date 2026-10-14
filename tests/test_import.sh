# Unit tests for scripts/import.sh.
# shellcheck shell=bash disable=SC2154 # SCRIPTS and FAKE_DOCKER_LOG come from tests/helpers.sh

import() { bash "$SCRIPTS/import.sh" "$@"; }

# release [DIR]: package a release from fake fetch output under DIR (default .); print its path.
release() {
  make_work "${1:-.}/work"
  bash "$SCRIPTS/package.sh" "${1:-.}/work" "${1:-.}/out" 2> /dev/null
}

# resum RELEASE: rewrite SHA256SUMS after a test changes a file on purpose.
# shellcheck disable=SC2094 # find skips SHA256SUMS, the file being written
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
  sed -i '/[ *]MANIFEST$/d' "$r/SHA256SUMS"
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
