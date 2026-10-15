#!/usr/bin/env bash
# import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]
# Both forges. Verifies every file in the release against SHA256SUMS before loading anything,
# loads the scanner images (and pushes them to PREFIX if given), then unpacks the databases into
# VULNDB_ROOT/incoming and swaps that in as VULNDB_ROOT/current, keeping the old one as
# VULNDB_ROOT/previous. A failure before the swap leaves current/ untouched.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

usage() { die "usage: import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]"; }
[[ $# -eq 2 || $# -eq 4 ]] || usage
release=$1 root=$2 registry=""
if [[ $# -eq 4 ]]; then
  [[ $3 == --registry && -n $4 ]] || usage
  registry=$4
fi
[[ -f $release/SHA256SUMS ]] || die "no SHA256SUMS in $release; is it a release directory?"

# covered FILE: stop unless SHA256SUMS lists FILE (with or without a binary-mode '*').
covered() {
  awk '{ sub(/^\*/, "", $2); print $2 }' "$release/SHA256SUMS" | grep -Fxq "$1" \
    || die "SHA256SUMS doesn't cover $1; nothing was loaded"
}

log "Verifying $release"
(cd "$release" && sha256sum -c --strict --quiet SHA256SUMS) \
  || die "checksum verification failed; nothing was loaded"
covered MANIFEST

manifest=$release/MANIFEST
version='^[0-9A-Za-z._-]+$'
name=$(manifest_get "$manifest" RELEASE '^scanners-[0-9]{4}-[0-9]{2}-[0-9]{2}$')
trivy_version=$(manifest_get "$manifest" TRIVY_VERSION "$version")
grype_version=$(manifest_get "$manifest" GRYPE_VERSION "$version")
trivy_image=$(manifest_get "$manifest" TRIVY_IMAGE '^airgap-vuln-scan/trivy:[0-9A-Za-z._-]+$')
grype_image=$(manifest_get "$manifest" GRYPE_IMAGE '^airgap-vuln-scan/grype:[0-9A-Za-z._-]+$')
trivy_tar=images/trivy-$trivy_version.tar.gz
grype_tar=images/grype-$grype_version.tar.gz
for f in "$trivy_tar" "$grype_tar" db/trivy-db.tar.gz db/trivy-java-db.tar.gz db/grype-db.tar.zst; do
  covered "$f"
done

log "Loading the scanner images"
docker load -q -i "$release/$trivy_tar"
docker load -q -i "$release/$grype_tar"
docker image inspect "$trivy_image" "$grype_image" > /dev/null \
  || die "the image archives don't hold $trivy_image and $grype_image"

# push_as IMAGE NAME: tag IMAGE as PREFIX/NAME and push it.
push_as() {
  docker tag "$1" "$registry/$2"
  docker push -q "$registry/$2"
}
if [[ -n $registry ]]; then
  log "Pushing to $registry"
  push_as "$trivy_image" "trivy:$trivy_version"
  push_as "$trivy_image" trivy:latest
  push_as "$grype_image" "grype:$grype_version"
  push_as "$grype_image" grype:latest
fi

log "Unpacking the databases"
incoming=$root/incoming
rm -rf "$incoming"
mkdir -p "$incoming/trivy" "$incoming/grype"
tar -xzf "$release/db/trivy-db.tar.gz" -C "$incoming/trivy"
tar -xzf "$release/db/trivy-java-db.tar.gz" -C "$incoming/trivy"
[[ -f $incoming/trivy/db/metadata.json && -f $incoming/trivy/java-db/metadata.json ]] \
  || die "the Trivy archives don't hold db/ and java-db/"
docker_run --network none -v "$(host_path "$incoming/grype"):/db/grype" \
  -v "$(host_path "$release/db"):/release:ro" "${GRYPE_OFFLINE[@]}" \
  "$grype_image" db import /release/grype-db.tar.zst
cp "$manifest" "$incoming/MANIFEST"

rm -rf "$root/previous"
if [[ -d $root/current ]]; then mv "$root/current" "$root/previous"; fi
mv "$incoming" "$root/current"
log "Imported $name into $root/current"
