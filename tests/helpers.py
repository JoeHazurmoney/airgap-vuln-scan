"""Shared setup for the Python unit tests: puts scripts/ on the import path, and gives each test
its own temporary directory and a fake docker, so no test needs Docker or a network."""

import contextlib
import importlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import lib  # noqa: E402 (needs the path above)


def script(name):
    """scripts/NAME.py as a module. `import`, a keyword, can't be imported with a statement."""
    return importlib.import_module(name)


class ScriptTest(unittest.TestCase):
    """Runs each test in a fresh temporary directory, with a clean environment and lib.docker
    replaced by a fake that records each call as one line (self.docker_calls) and succeeds,
    unless the call starts with one of the prefixes in self.docker_fails."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(tmp.name)
        for patcher in (mock.patch.dict(os.environ), mock.patch.object(lib, "docker", self.fake_docker)):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop("GITHUB_ACTIONS", None)
        self.docker_calls = []
        self.docker_fails = []

    def fake_docker(self, *args, output=False):
        call = " ".join(args)
        self.docker_calls.append(call)
        if any(call.startswith(prefix) for prefix in self.docker_fails):
            raise lib.Fail(f"docker {args[0]} failed (exit 1)")
        return ""

    def run_script(self, module, *args):
        """Runs a script's main as its command line would; returns the exit status and everything
        it printed, stdout and stderr together."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                lib.run(module.main, [str(arg) for arg in args])
            except SystemExit as e:
                return e.code, out.getvalue()
        return 0, out.getvalue()
