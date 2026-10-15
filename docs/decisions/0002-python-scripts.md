# ADR-0002: Python, not bash, for the pipeline scripts

**Status:** Accepted
**Date:** 2026-10-15
**Deciders:** Repository owner

## Context

The pipeline is five bash scripts and a shared `lib.sh`, about 350 lines, with about 500 lines of
bash tests. They work, but to read or fix them you need to know `set -euo pipefail`, `sed` used as
a JSON parser, GNU `date` arithmetic, quoting rules, and Git Bash workarounds (`pwd -W`,
`MSYS_NO_PATHCONV`). More people can read and fix Python, which matters for an example meant to be
copied ([#3](https://github.com/JoeHazurmoney/airgap-vuln-scan/issues/3)).

The scripts run on the forges' hosts, both connected and disconnected, which run RHEL 9 or RHEL 10.
Nothing can be installed on the disconnected side unless it's carried across the gap.

### What the hosts have

Checked in the UBI images, which carry the same `python3` packages as RHEL:

| Host | `python3` | `tarfile` filters |
|---|---|---|
| RHEL 9.8 (`ubi9/ubi:9.8`) | 3.9.25 | yes |
| RHEL 10.2 (`ubi10/ubi:10.2`) | 3.12.15 | yes |
| GitHub's `ubuntu-24.04` runner | 3.12 | yes |

On both RHEL versions `dnf` is written in Python and depends on `python3`, so any host with `dnf`
has it. Python 3.9 reached its upstream end of life in October 2025, but RHEL 9 still supports it.

### The spike

`scripts/import.py` is a port of `scripts/import.sh`, chosen because it does the most: checksums,
archives, manifest parsing and Docker calls. Both versions sit side by side. The demo workflow
runs the Python one for the disconnected forge's import and for the changed-file check, against a
real 1.4 GB release. The bash one still does the connected forge's import.

| | bash | Python |
|---|---|---|
| Lines in `import` | 78 | 144 |
| Lines in `lib` | 88, for all five scripts | 71, only what `import` needs |
| Unit tests for `import` and `lib` | 23, 13.5 s in Git Bash, 2 s on Linux | 26, 0.06 s (plus about 1 s to start the container) |
| Checksums | `sha256sum -c --strict`, plus `awk` and `grep` to check that a file is listed | `hashlib`, read in chunks; accepts both `hash  file` and `hash *file` |
| Archives | `tar -xzf`: GNU tar's defaults decide what's refused | `tarfile` with `filter="data"`: `..`, absolute links, links out of the directory and device files are refused, and a test proves it |
| Docker calls | strings, quoted by hand | argument lists |
| Windows paths | `pwd -W` and `MSYS_NO_PATHCONV` | none needed |

The Python version is longer, because it spells out what `sha256sum` and `tar` did. But each line
does one visible thing, and a reader needs only Python, not bash, coreutils and GNU tar.

The errors read better where it matters, and are the same where the demo depends on them:

| Failure | bash | Python |
|---|---|---|
| A changed byte | `db/grype-db.tar.zst: FAILED`, `sha256sum: WARNING: 1 computed checksum did NOT match`, `ERROR: checksum verification failed; nothing was loaded` | the same, without the `sha256sum` line |
| No Docker | `scripts/import.sh: line 44: docker: command not found` (exit 127) | `ERROR: docker not found` (exit 1) |
| A broken archive | `gzip: stdin: not in gzip format`, `tar: Child returned status 1`, `tar: Error is not recoverable: exiting now` (exit 2) | `ERROR: can't unpack r/db/trivy-java-db.tar.gz: not a gzip file` (exit 1) |
| A wrong argument | `ERROR: usage: import.sh RELEASE_DIR VULNDB_ROOT [--registry PREFIX]` (exit 1) | `argparse`'s usage line and the missing argument's name (exit 2), plus `--help` |

## Decision

**Go: port the scripts to Python.**

* **Python 3.9 or later, standard library only.** If nothing needs `pip install`, nothing extra has
  to be carried across the gap.
* **Write for 3.9, test on 3.9 and 3.12.** The unit tests run in the `ubi9/ubi` and `ubi10/ubi`
  images, which hold RHEL's own builds rather than upstream's, the same way on a PC and in CI.
* **`unittest`, not pytest**, so the tests need no install either. Docker is replaced by a fake at
  `lib.docker`, so no test needs Docker or a network.
* **No Python on the PC.** The tests run in those containers, and Docker is already needed for the
  end-to-end run.
* **The port is a follow-up issue.** Port the other four scripts one at a time, and remove each
  bash script, with its tests, when its Python version lands. The demo workflow's steps stay as they
  are, so CI shows that each port behaves the same.

### Writing for 3.9

* No `match` statements, and no `X | Y` type unions at run time (both 3.10).
* No `datetime.UTC` (3.11): use `timezone.utc`.
* 3.9's `datetime.fromisoformat` can't read Trivy's build times (a trailing `Z` and nine digits of
  fractions), so parse them explicitly.
* No `hashlib.file_digest` (3.11): hash files in chunks, as `import.py` does.
* `tarfile`'s `filter="data"` exists on 3.9 only from 3.9.17. RHEL 9.8's 3.9.25 has it. On an older
  Python, `import.py` refuses to unpack anything, and says so.

## Options considered

### Option A: keep bash

* Nothing changes, and the scripts already pass the demo.
* The things that make bash hard to read (above) stay, and grow with every feature.

### Option B: Python, standard library only (chosen)

* Python 3.9 or 3.12 is already on every RHEL 9 and RHEL 10 host.
* The scripts get longer, and run on both 3.9 and 3.12 for as long as RHEL 9 is in use.

### Option C: Python with packages (e.g. pytest, requests)

* Somewhat shorter code and tests.
* Every package, and its dependencies, has to be carried across the gap and kept up to date. That
  is more work than the shorter code saves.

## Consequences

* **Host requirements change once the port is done:** Docker and `python3` 3.9 or later, in
  place of bash, coreutils, curl, tar and gzip. This replaces the line about the host in
  [ADR-0001](0001-scanner-images-and-databases.md)'s consequences. Until then, the hosts need both.
* **3.9 sets the limits for as long as RHEL 9 is a target.** When it isn't, raise the minimum and
  drop the workarounds above.
* **`import` has 16 Python unit tests**, against 11 in bash, including an archive with a path that
  points outside, a checksum file that isn't text, and a Python with no `tarfile` filters.
