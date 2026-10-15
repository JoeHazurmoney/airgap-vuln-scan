#!/usr/bin/env python3
"""import.py RELEASE_DIR VULNDB_ROOT [--registry PREFIX]

Both forges. Verifies every file in the release against SHA256SUMS before loading anything,
loads the scanner images (and pushes them to PREFIX if given), then unpacks the databases into
VULNDB_ROOT/incoming and swaps that in as VULNDB_ROOT/current, keeping the old one as
VULNDB_ROOT/previous. A failure before the swap leaves current/ untouched.
"""

import argparse
import hashlib
import re
import shutil
import tarfile
import zlib
from pathlib import Path

import lib

VERSION = r"[0-9A-Za-z._-]+"


def sha256(path):
    """A file's SHA-256, read 1 MiB at a time (hashlib.file_digest needs Python 3.11)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(release):
    """Checks every file SHA256SUMS lists, as `sha256sum -c --strict` does, printing a line for
    each that fails. Accepts text ('HASH  FILE') and binary ('HASH *FILE') lines. Returns the
    names of the files checked."""
    names, failed = set(), False
    lines = (release / "SHA256SUMS").read_text().splitlines()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if not match:
            lib.log(f"SHA256SUMS line {number} isn't 'HASH  FILE'")
            failed = True
            continue
        expected, name = match.groups()
        names.add(name)
        try:
            same = sha256(release / name) == expected.lower()
        except OSError:
            lib.log(f"{name}: FAILED open or read")
            failed = True
            continue
        if not same:
            lib.log(f"{name}: FAILED")
            failed = True
    if failed or not names:
        raise lib.Fail("checksum verification failed; nothing was loaded")
    return names


def extract(archive, directory):
    """Unpacks a .tar.gz into DIRECTORY with tarfile's "data" filter, which refuses absolute
    paths, '..', links that point outside DIRECTORY, and device files (Python 3.9.17 or later;
    RHEL 9's 3.9 has it too)."""
    if not hasattr(tarfile, "data_filter"):
        raise lib.Fail("this Python's tarfile can't refuse unsafe paths; use 3.9.17 or later")
    try:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(directory, filter="data")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise lib.Fail(f"can't unpack {archive}: {e}") from None


def main(argv):
    parser = argparse.ArgumentParser(prog="import.py", description=__doc__.split("\n\n")[1])
    parser.add_argument("release", metavar="RELEASE_DIR", type=Path)
    parser.add_argument("root", metavar="VULNDB_ROOT", type=Path)
    parser.add_argument("--registry", metavar="PREFIX", help="also push the images to PREFIX")
    args = parser.parse_args(argv)
    release, root = args.release, args.root
    if not (release / "SHA256SUMS").is_file():
        raise lib.Fail(f"no SHA256SUMS in {release}; is it a release directory?")

    lib.log(f"Verifying {release}")
    checked = verify(release)

    def covered(name):
        if name not in checked:
            raise lib.Fail(f"SHA256SUMS doesn't cover {name}; nothing was loaded")

    covered("MANIFEST")
    manifest = release / "MANIFEST"
    name = lib.manifest_get(manifest, "RELEASE", r"scanners-[0-9]{4}-[0-9]{2}-[0-9]{2}")
    trivy_version = lib.manifest_get(manifest, "TRIVY_VERSION", VERSION)
    grype_version = lib.manifest_get(manifest, "GRYPE_VERSION", VERSION)
    trivy_image = lib.manifest_get(manifest, "TRIVY_IMAGE", "airgap-vuln-scan/trivy:" + VERSION)
    grype_image = lib.manifest_get(manifest, "GRYPE_IMAGE", "airgap-vuln-scan/grype:" + VERSION)
    trivy_tar = f"images/trivy-{trivy_version}.tar.gz"
    grype_tar = f"images/grype-{grype_version}.tar.gz"
    for f in (trivy_tar, grype_tar, "db/trivy-db.tar.gz", "db/trivy-java-db.tar.gz",
              "db/grype-db.tar.zst"):
        covered(f)

    lib.log("Loading the scanner images")
    lib.docker("load", "-q", "-i", str(release / trivy_tar))
    lib.docker("load", "-q", "-i", str(release / grype_tar))
    try:
        lib.docker("image", "inspect", trivy_image, grype_image, output=True)
    except lib.Fail:
        raise lib.Fail(f"the image archives don't hold {trivy_image} and {grype_image}") from None

    if args.registry:
        lib.log(f"Pushing to {args.registry}")
        for image, ref in ((trivy_image, f"trivy:{trivy_version}"), (trivy_image, "trivy:latest"),
                           (grype_image, f"grype:{grype_version}"), (grype_image, "grype:latest")):
            lib.docker("tag", image, f"{args.registry}/{ref}")
            lib.docker("push", "-q", f"{args.registry}/{ref}")

    lib.log("Unpacking the databases")
    incoming = root / "incoming"
    if incoming.exists():
        shutil.rmtree(incoming)
    (incoming / "trivy").mkdir(parents=True)
    (incoming / "grype").mkdir()
    extract(release / "db/trivy-db.tar.gz", incoming / "trivy")
    extract(release / "db/trivy-java-db.tar.gz", incoming / "trivy")
    if not all((incoming / "trivy" / d / "metadata.json").is_file() for d in ("db", "java-db")):
        raise lib.Fail("the Trivy archives don't hold db/ and java-db/")
    lib.docker_run("--network", "none", "-v", f"{lib.host_path(incoming / 'grype')}:/db/grype",
                   "-v", f"{lib.host_path(release / 'db')}:/release:ro", *lib.GRYPE_OFFLINE,
                   grype_image, "db", "import", "/release/grype-db.tar.zst")
    shutil.copyfile(manifest, incoming / "MANIFEST")

    current, previous = root / "current", root / "previous"
    if previous.exists():
        shutil.rmtree(previous)
    if current.exists():
        current.rename(previous)
    incoming.rename(current)
    lib.log(f"Imported {name} into {current}")


if __name__ == "__main__":
    lib.run(main)
