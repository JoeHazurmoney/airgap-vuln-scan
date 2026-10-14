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
