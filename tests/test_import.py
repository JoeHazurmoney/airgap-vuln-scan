"""Unit tests for scripts/import.py."""

import hashlib
import io
import os
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import ScriptTest, script

import_py = script("import")

MANIFEST = """RELEASE=scanners-2026-10-14
CREATED=2026-10-14T07:01:00Z
TRIVY_VERSION=0.75.0
TRIVY_SOURCE=ghcr.io/aquasecurity/trivy@sha256:1111111111111111111111111111111111111111111111111111111111111111
TRIVY_IMAGE=airgap-vuln-scan/trivy:0.75.0
GRYPE_VERSION=0.120.1
GRYPE_SOURCE=ghcr.io/anchore/grype@sha256:2222222222222222222222222222222222222222222222222222222222222222
GRYPE_IMAGE=airgap-vuln-scan/grype:0.120.1
TRIVY_DB_BUILT=2026-10-13T06:20:16Z
TRIVY_JAVA_DB_BUILT=2026-10-13T01:02:03Z
GRYPE_DB_BUILT=2026-10-14T06:00:00Z
"""


def make_tar(path, files=None, links=None):
    """A .tar.gz holding FILES ({name: bytes}) and symbolic LINKS ({name: target})."""
    with tarfile.open(path, "w:gz") as tar:
        for name, data in (files or {}).items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            tar.addfile(info)


def resum(release):
    """Rewrites SHA256SUMS as package.sh does, after a test changes a file on purpose."""
    names = sorted(p.relative_to(release).as_posix() for p in release.rglob("*")
                   if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{hashlib.sha256((release / n).read_bytes()).hexdigest()}  {n}\n" for n in names]
    (release / "SHA256SUMS").write_text("".join(lines))


def make_release(parent="."):
    """A release as package.sh leaves it, with small fake images and databases."""
    release = Path(parent) / "scanners-2026-10-14"
    (release / "images").mkdir(parents=True)
    (release / "db").mkdir()
    (release / "images/trivy-0.75.0.tar.gz").write_bytes(b"fake trivy image")
    (release / "images/grype-0.120.1.tar.gz").write_bytes(b"fake grype image")
    make_tar(release / "db/trivy-db.tar.gz", {
        "db/trivy.db": b"fake trivy db",
        "db/metadata.json": b'{"Version":2,"UpdatedAt":"2026-10-13T06:20:16.5Z"}'})
    make_tar(release / "db/trivy-java-db.tar.gz", {
        "java-db/trivy-java.db": b"fake java db",
        "java-db/metadata.json": b'{"Version":1,"UpdatedAt":"2026-10-13T01:02:03.123456789Z"}'})
    (release / "db/grype-db.tar.zst").write_bytes(b"fake grype archive")
    (release / "MANIFEST").write_text(MANIFEST)
    resum(release)
    return release


class Import(ScriptTest):
    def run_import(self, *args):
        return self.run_script(import_py, *args)

    def test_imports_a_release_into_current(self):
        r = make_release()
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 0, out)
        for f in ("MANIFEST", "trivy/db/metadata.json", "trivy/java-db/metadata.json"):
            self.assertTrue(Path("root/current", f).is_file(), f"current/ has no {f}")
        self.assertTrue(Path("root/current/grype").is_dir())
        self.assertFalse(Path("root/incoming").exists())
        calls = "\n".join(self.docker_calls)
        self.assertIn(f"load -q -i {r / 'images/trivy-0.75.0.tar.gz'}", calls)
        self.assertIn(f"load -q -i {r / 'images/grype-0.120.1.tar.gz'}", calls)
        grype_import = self.docker_calls[-1]
        self.assertIn("--network none", grype_import)
        self.assertIn(f"-v {os.path.abspath('root/incoming/grype')}:/db/grype ", grype_import)
        self.assertIn("GRYPE_DB_AUTO_UPDATE=false", grype_import)
        self.assertTrue(grype_import.endswith(" db import /release/grype-db.tar.zst"))

    def test_a_second_import_keeps_the_first_as_previous(self):
        r = make_release()
        self.run_import(r, "root")
        Path("root/current/first").touch()
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 0, out)
        self.assertTrue(Path("root/previous/first").exists(), "previous/ isn't the first import")
        self.assertFalse(Path("root/current/first").exists(), "current/ wasn't replaced")

    def test_a_changed_file_is_refused_before_anything_is_loaded(self):
        r = make_release()
        self.run_import(r, "root")
        before = Path("root/current/MANIFEST").read_text()
        self.docker_calls.clear()
        with open(r / "db/grype-db.tar.zst", "ab") as f:
            f.write(b"x")
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("db/grype-db.tar.zst: FAILED", out)
        self.assertIn("nothing was loaded", out)
        self.assertEqual(self.docker_calls, [])
        self.assertEqual(Path("root/current/MANIFEST").read_text(), before)

    def test_a_missing_file_is_refused(self):
        r = make_release()
        (r / "db/trivy-java-db.tar.gz").unlink()
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("db/trivy-java-db.tar.gz: FAILED open or read", out)
        self.assertIn("nothing was loaded", out)
        self.assertFalse(Path("root/current").exists(), "current/ was created")

    def test_the_checksums_must_cover_every_file_used(self):
        for name in ("MANIFEST", "images/trivy-0.75.0.tar.gz", "images/grype-0.120.1.tar.gz",
                     "db/trivy-db.tar.gz", "db/trivy-java-db.tar.gz", "db/grype-db.tar.zst"):
            with self.subTest(name):
                r = make_release(name.replace("/", "_"))
                sums = r / "SHA256SUMS"
                sums.write_text("".join(line for line in sums.read_text().splitlines(True)
                                        if not line.endswith(f"  {name}\n")))
                code, out = self.run_import(r, "root")
                self.assertEqual(code, 1)
                self.assertIn(f"SHA256SUMS doesn't cover {name}; nothing was loaded", out)
                self.assertEqual(self.docker_calls, [])

    def test_binary_mode_checksums_are_accepted(self):
        r = make_release()
        sums = r / "SHA256SUMS"
        sums.write_text(sums.read_text().replace("  ", " *"))
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 0, out)
        self.assertTrue(Path("root/current/MANIFEST").is_file())

    def test_a_malformed_checksum_line_is_refused(self):
        r = make_release()
        with open(r / "SHA256SUMS", "a") as f:
            f.write("not a checksum line\n")
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("SHA256SUMS line 7", out)
        self.assertIn("nothing was loaded", out)

    def test_a_checksum_file_that_is_not_text_is_refused(self):
        r = make_release()
        with open(r / "SHA256SUMS", "ab") as f:
            f.write(b"\xff\xfe\x00\x01\n")
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("SHA256SUMS line 7", out)
        self.assertIn("nothing was loaded", out)

    def test_a_manifest_value_that_could_escape_the_release_is_refused(self):
        r = make_release()
        manifest = r / "MANIFEST"
        manifest.write_text(manifest.read_text().replace("TRIVY_VERSION=0.75.0", "TRIVY_VERSION=../../x"))
        resum(r)
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("unexpected TRIVY_VERSION", out)

    def test_images_that_do_not_match_the_manifest_are_refused(self):
        r = make_release()
        self.docker_fails = ["image inspect"]
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("the image archives don't hold airgap-vuln-scan/trivy:0.75.0 and "
                      "airgap-vuln-scan/grype:0.120.1", out)
        self.assertFalse(Path("root/current").exists())

    def test_a_broken_archive_leaves_current_untouched(self):
        r = make_release()
        self.run_import(r, "root")
        before = Path("root/current/MANIFEST").read_text()
        (r / "db/trivy-java-db.tar.gz").write_bytes(b"not a tar")
        resum(r)
        code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("can't unpack", out)
        self.assertEqual(Path("root/current/MANIFEST").read_text(), before)
        self.assertTrue(Path("root/current/trivy/java-db/metadata.json").is_file(), "current/ was damaged")

    def test_an_archive_entry_that_points_outside_is_refused(self):
        # Each archive also holds what a real one does, so only the unsafe entry can stop it.
        db = {"db/trivy.db": b"fake trivy db", "db/metadata.json": b"{}"}
        unsafe = {"dotdot": {"files": {**db, "db/../../outside": b"x"}},
                  "absolute-link": {"files": db, "links": {"db/passwd": "/etc/passwd"}},
                  "link-out": {"files": db, "links": {"db/up": "../../.."}}}
        for case, members in unsafe.items():
            with self.subTest(case):
                r = make_release(case)
                make_tar(r / "db/trivy-db.tar.gz", **members)
                resum(r)
                code, out = self.run_import(r, f"{case}/root")
                self.assertEqual(code, 1)
                self.assertIn("can't unpack", out)
                self.assertFalse(Path(f"{case}/root/current").exists())
                self.assertEqual(list(Path(".").rglob("outside")), [])

    def test_a_python_without_tarfile_filters_refuses_to_unpack(self):
        # Python 3.9 before 3.9.17 has no filters, and would unpack whatever an archive holds.
        r = make_release()
        with mock.patch.dict(vars(tarfile)):
            del vars(tarfile)["data_filter"]
            code, out = self.run_import(r, "root")
        self.assertEqual(code, 1)
        self.assertIn("can't refuse unsafe paths; use 3.9.17 or later", out)
        self.assertFalse(Path("root/current").exists())

    def test_paths_with_spaces_work(self):
        r = make_release("a b")
        code, out = self.run_import(r, "a b/root")
        self.assertEqual(code, 0, out)
        self.assertTrue(Path("a b/root/current/MANIFEST").is_file())

    def test_pushes_to_a_registry_when_asked(self):
        r = make_release()
        code, out = self.run_import(r, "root", "--registry", "registry.internal/scanners")
        self.assertEqual(code, 0, out)
        for image, ref in (("trivy:0.75.0", "trivy:0.75.0"), ("trivy:0.75.0", "trivy:latest"),
                           ("grype:0.120.1", "grype:0.120.1"), ("grype:0.120.1", "grype:latest")):
            self.assertIn(f"tag airgap-vuln-scan/{image} registry.internal/scanners/{ref}", self.docker_calls)
            self.assertIn(f"push -q registry.internal/scanners/{ref}", self.docker_calls)

    def test_not_a_release_directory(self):
        Path("empty").mkdir()
        code, out = self.run_import("empty", "root")
        self.assertEqual(code, 1)
        self.assertIn("no SHA256SUMS in empty", out)


if __name__ == "__main__":
    unittest.main()
