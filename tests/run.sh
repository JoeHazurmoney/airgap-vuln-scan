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
  file=$(cd "$(dirname "$file")" && pwd)/$(basename "$file") # each test runs in its own directory
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
