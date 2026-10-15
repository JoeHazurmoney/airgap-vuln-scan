#!/usr/bin/env bash
# fetch.sh WORK_DIR [--java-db-refresh-days N]
# Connected side. Pulls the latest official Trivy and Grype images, pins each by digest and
# tags it airgap-vuln-scan/<tool>:<version>, then downloads the databases into WORK_DIR:
# Trivy's into WORK_DIR/trivy, Grype's archive to WORK_DIR/grype-db.tar.zst. Trivy's Java
# index is downloaded again only once it's more than N days old (default 0: every time).
# Writes WORK_DIR/fetch.env for package.sh.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

TRIVY_IMAGE_REF=${TRIVY_IMAGE_REF:-ghcr.io/aquasecurity/trivy:latest}
GRYPE_IMAGE_REF=${GRYPE_IMAGE_REF:-ghcr.io/anchore/grype:latest}

usage() { die "usage: fetch.sh WORK_DIR [--java-db-refresh-days N]"; }
[[ $# -eq 1 || $# -eq 3 ]] || usage
work=$1 refresh_days=0
if [[ $# -eq 3 ]]; then
  [[ $2 == --java-db-refresh-days && $3 =~ ^[0-9]+$ ]] || usage
  refresh_days=$3
fi
mkdir -p "$work/trivy"
cache=$(host_path "$work/trivy")

# pin REF TOOL VERSION_COMMAND: pull REF and tag it airgap-vuln-scan/TOOL:VERSION. Prints
# "SOURCE IMAGE VERSION", where SOURCE is REF pinned by digest.
pin() {
  local source version
  docker pull -q "$1" > /dev/null
  source=$(docker image inspect --format '{{index .RepoDigests 0}}' "$1")
  version=$(docker_run "$source" "$3" | sed -n 's/^Version: *v\{0,1\}//p' | head -n 1)
  [[ $version =~ ^[0-9A-Za-z._-]+$ ]] || die "couldn't read $2's version from $source"
  docker tag "$source" "airgap-vuln-scan/$2:$version"
  printf '%s %s %s\n' "$source" "airgap-vuln-scan/$2:$version" "$version"
}

log "Pulling $TRIVY_IMAGE_REF and $GRYPE_IMAGE_REF"
pinned=$(pin "$TRIVY_IMAGE_REF" trivy --version)
read -r trivy_source trivy_image trivy_version <<< "$pinned"
pinned=$(pin "$GRYPE_IMAGE_REF" grype version)
read -r grype_source grype_image grype_version <<< "$pinned"

trivy_args=(--cache-dir /cache --skip-version-check --disable-telemetry --no-progress)
log "Downloading Trivy's database"
docker_run -v "$cache:/cache" "$trivy_image" image --download-db-only "${trivy_args[@]}"

java_meta=$work/trivy/java-db/metadata.json
if (( refresh_days > 0 )) && [[ -f $java_meta ]] && ! older_than "$(trivy_built "$java_meta")" "$refresh_days"; then
  log "Reusing Trivy's Java database (built $(trivy_built "$java_meta")); it's downloaded again after $refresh_days days"
else
  log "Downloading Trivy's Java database"
  docker_run -v "$cache:/cache" "$trivy_image" image --download-java-db-only "${trivy_args[@]}"
fi

log "Downloading Grype's database"
listing=$(docker_run "$grype_image" db list)
url=$(sed -n 's/^DB URL: *//p' <<< "$listing")
checksum=$(sed -n 's/^Checksum: *sha256://p' <<< "$listing")
grype_built=$(docker_run "$grype_image" db list -o json | sed -n 's/.*"built" *: *"\([^"]*\)".*/\1/p')
[[ $url == https://* && $checksum =~ ^[0-9a-f]{64}$ && -n $grype_built ]] \
  || die "couldn't read Grype's database listing"
curl -fsSL --retry 3 -o "$work/grype-db.tar.zst.part" "$url"
actual=$(sha256sum "$work/grype-db.tar.zst.part" | cut -d ' ' -f 1)
[[ $actual == "$checksum" ]] || die "Grype's database doesn't match its listing (sha256 $actual, expected $checksum)"
mv "$work/grype-db.tar.zst.part" "$work/grype-db.tar.zst"

trivy_db_built=$(trivy_built "$work/trivy/db/metadata.json")
java_db_built=$(trivy_built "$java_meta")
cat > "$work/fetch.env" <<EOF
TRIVY_VERSION=$trivy_version
TRIVY_SOURCE=$trivy_source
TRIVY_IMAGE=$trivy_image
GRYPE_VERSION=$grype_version
GRYPE_SOURCE=$grype_source
GRYPE_IMAGE=$grype_image
TRIVY_DB_BUILT=$trivy_db_built
TRIVY_JAVA_DB_BUILT=$java_db_built
GRYPE_DB_BUILT=$grype_built
EOF
log "Fetched Trivy $trivy_version and Grype $grype_version, with their databases, into $work"
