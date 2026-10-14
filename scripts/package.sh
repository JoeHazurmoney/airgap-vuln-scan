#!/usr/bin/env bash
# package.sh WORK_DIR OUT_DIR
# Connected side. Packages what fetch.sh left in WORK_DIR as OUT_DIR/scanners-YYYY-MM-DD/ (the
# UTC date; a re-run on the same day replaces it), and prints that path.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

[[ $# -eq 2 ]] || die "usage: package.sh WORK_DIR OUT_DIR"
work=$1 out=$2
[[ -f $work/fetch.env ]] || die "no fetch.env in $work; run fetch.sh first"

trivy_image=$(manifest_get "$work/fetch.env" TRIVY_IMAGE)
trivy_version=$(manifest_get "$work/fetch.env" TRIVY_VERSION)
grype_image=$(manifest_get "$work/fetch.env" GRYPE_IMAGE)
grype_version=$(manifest_get "$work/fetch.env" GRYPE_VERSION)

name=scanners-$(date -u +%Y-%m-%d)
release=$out/$name
rm -rf "$release"
mkdir -p "$release/images" "$release/db"

log "Saving the scanner images"
docker save "$trivy_image" | gzip > "$release/images/trivy-$trivy_version.tar.gz"
docker save "$grype_image" | gzip > "$release/images/grype-$grype_version.tar.gz"

log "Packing the databases"
tar -czf "$release/db/trivy-db.tar.gz" -C "$work/trivy" db
tar -czf "$release/db/trivy-java-db.tar.gz" -C "$work/trivy" java-db
cp "$work/grype-db.tar.zst" "$release/db/grype-db.tar.zst"

{
  printf 'RELEASE=%s\n' "$name"
  printf 'CREATED=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat "$work/fetch.env"
} > "$release/MANIFEST"

# shellcheck disable=SC2094 # find skips SHA256SUMS, the file being written
(cd "$release" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
  | xargs sha256sum > SHA256SUMS)
log "Packaged $release ($(du -sh "$release" | cut -f1))"
printf '%s\n' "$release"
