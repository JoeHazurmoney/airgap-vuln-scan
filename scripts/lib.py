"""Shared helpers for the airgap-vuln-scan scripts. Python 3.9 or later, standard library only."""

import os
import re
import subprocess
import sys
from pathlib import Path


class Fail(Exception):
    """An error to report as 'ERROR: message', with exit status 1."""


def run(main, argv=None):
    """Runs a script's main(argv), reporting a Fail or an OSError (a missing file, a full disk)
    as one ERROR line on stderr, with exit status 1."""
    try:
        main(sys.argv[1:] if argv is None else argv)
    except (Fail, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def log(message):
    """Progress, on stderr (stdout is kept for results)."""
    print(message, file=sys.stderr)


def manifest_get(path, key, pattern=None):
    """KEY's value in a KEY=value file, which must match the regular expression PATTERN in full
    if one is given. Read as text, never run: the file may have come from removable media."""
    values = [line[len(key) + 1:] for line in Path(path).read_text().splitlines()
              if line.startswith(key + "=")]
    if not values or not values[0]:
        raise Fail(f"{key} not found in {path}")
    if pattern and not re.fullmatch(pattern, values[0]):
        raise Fail(f"unexpected {key} in {path}: '{values[0]}'")
    return values[0]


def docker(*args, output=False):
    """Runs docker with ARGS, a list, so nothing needs quoting. Returns its stdout if output is
    true; otherwise it goes straight through."""
    try:
        result = subprocess.run(["docker", *args], stdout=subprocess.PIPE if output else None,
                                text=True)
    except FileNotFoundError:
        raise Fail("docker not found") from None
    if result.returncode != 0:
        raise Fail(f"docker {args[0]} failed (exit {result.returncode})")
    return result.stdout


def docker_run(*args, output=False):
    """docker run as the host user, so files written to bind mounts belong to the runner, with a
    private writable /tmp: Grype's image is FROM scratch and its /tmp belongs to root, and without
    an explicit mode Docker copies that mode onto the tmpfs. Windows has no user IDs, and Docker
    Desktop's mounts don't need them."""
    user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    return docker("run", "--rm", *user, "--tmpfs", "/tmp:mode=1777", "-e", "HOME=/tmp", *args,
                  output=output)


def host_path(path):
    """PATH (a directory or a file) as an absolute path, which Docker needs to bind-mount it."""
    return os.path.abspath(path)


# The settings that keep Grype offline, with its database mounted at /db/grype.
GRYPE_OFFLINE = ["-e", "GRYPE_DB_CACHE_DIR=/db/grype", "-e", "GRYPE_DB_AUTO_UPDATE=false",
                 "-e", "GRYPE_DB_VALIDATE_AGE=false", "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false"]
