#!/usr/bin/env bash
# scan.sh VULNDB_DIR IMAGE_TAR [REPORTS_DIR]
# Both forges. Checks the databases' age, then scans IMAGE_TAR (from `docker save`) with Trivy
# and Grype, each with no network and the databases mounted read-only. Tables go to stdout and
# JSON reports to REPORTS_DIR (default ./reports). Findings don't fail the scan.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

[[ $# -eq 2 || $# -eq 3 ]] || die "usage: scan.sh VULNDB_DIR IMAGE_TAR [REPORTS_DIR]"
db=$1 image_tar=$2 reports=${3:-reports}
[[ -f $image_tar ]] || die "$image_tar not found"
bash "$(dirname "$0")/check-age.sh" "$db"

trivy_image=${TRIVY_IMAGE:-$(manifest_get "$db/MANIFEST" TRIVY_IMAGE)}
grype_image=${GRYPE_IMAGE:-$(manifest_get "$db/MANIFEST" GRYPE_IMAGE)}
mkdir -p "$reports"
mounts=(-v "$(host_path "$db"):/db:ro" -v "$(host_path "$image_tar"):/scan/image.tar:ro"
  -v "$(host_path "$reports"):/reports")

log "Trivy ($trivy_image)"
docker_run --network none "${mounts[@]}" "$trivy_image" image --input /scan/image.tar \
  "${TRIVY_OFFLINE[@]}" --cache-backend memory --scanners vuln --no-progress \
  --format json --output /reports/trivy.json
docker_run --network none "${mounts[@]}" "$trivy_image" convert --format table /reports/trivy.json

log "Grype ($grype_image)"
docker_run --network none "${mounts[@]}" "${GRYPE_OFFLINE[@]}" "$grype_image" \
  docker-archive:/scan/image.tar -o table -o json=/reports/grype.json

log "Reports in $reports"
