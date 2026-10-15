"""Unit tests for scripts/lib.py."""

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from helpers import ScriptTest, lib

real_docker = lib.docker  # ScriptTest replaces lib.docker with a fake


class ManifestGet(ScriptTest):
    def test_reads_a_value(self):
        Path("m").write_text("A=1\nTRIVY_VERSION=0.75.0\n")
        self.assertEqual(lib.manifest_get("m", "TRIVY_VERSION"), "0.75.0")

    def test_fails_on_a_missing_key(self):
        Path("m").write_text("A=1\n")
        with self.assertRaisesRegex(lib.Fail, "B not found in m"):
            lib.manifest_get("m", "B")

    def test_a_longer_key_is_a_different_key(self):
        Path("m").write_text("TRIVY_VERSION_OLD=0.74.0\n")
        with self.assertRaisesRegex(lib.Fail, "TRIVY_VERSION not found"):
            lib.manifest_get("m", "TRIVY_VERSION")

    def test_rejects_a_value_that_does_not_match(self):
        Path("m").write_text("TRIVY_VERSION=../../etc\n")
        with self.assertRaisesRegex(lib.Fail, "unexpected TRIVY_VERSION in m: '../../etc'"):
            lib.manifest_get("m", "TRIVY_VERSION", "[0-9A-Za-z._-]+")


class Docker(ScriptTest):
    def test_passes_arguments_unquoted_and_returns_output(self):
        done = subprocess.CompletedProcess([], 0, stdout='{"built": "x y"}')
        with mock.patch("subprocess.run", return_value=done) as run:
            self.assertEqual(real_docker("run", "a b", "c", output=True), '{"built": "x y"}')
        self.assertEqual(run.call_args.args[0], ["docker", "run", "a b", "c"])

    def test_a_failure_names_the_command_and_its_status(self):
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 125)):
            with self.assertRaisesRegex(lib.Fail, r"docker load failed \(exit 125\)"):
                real_docker("load", "-i", "x")

    def test_no_docker_installed(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(lib.Fail, "docker not found"):
                real_docker("version")

    def test_docker_run_gives_containers_a_writable_tmp(self):
        # Grype's image is FROM scratch with a root-owned /tmp, and containers run as the host user.
        # Without an explicit mode, Docker copies that /tmp's root-only mode onto the tmpfs.
        lib.docker_run("some/image")
        self.assertIn("--tmpfs /tmp:mode=1777", self.docker_calls[0])

    @unittest.skipUnless(hasattr(os, "getuid"), "no user IDs on Windows")
    def test_docker_run_runs_as_the_host_user(self):
        lib.docker_run("some/image")
        self.assertIn(f"--user {os.getuid()}:{os.getgid()}", self.docker_calls[0])


class HostPath(ScriptTest):
    def test_is_absolute_for_dirs_and_files(self):
        Path("d d").mkdir()
        Path("d d/f").touch()
        self.assertTrue(os.path.isabs(lib.host_path("d d")))
        self.assertEqual(lib.host_path(Path("d d/f")), os.path.join(lib.host_path("d d"), "f"))


if __name__ == "__main__":
    unittest.main()
