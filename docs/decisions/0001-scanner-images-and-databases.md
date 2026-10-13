# ADR-0001: Official scanner images, with their databases in a mounted directory

**Status:** Accepted
**Date:** 2026-10-13
**Deciders:** Repository owner

## Context

Trivy and Grype each need two things to scan an image: the scanner itself and a vulnerability
database. On a system with no internet, both have to be carried across the gap. They behave very
differently:

| | Scanner images | Databases |
|---|---|---|
| Changes | every few weeks (a tool release) | Trivy's every 6 hours; its Java index and Grype's daily |
| Size (compressed) | tens of MB each | trivy-db 133 MB, trivy-java-db 983 MB, Grype 190 MB |
| Where they come from | `ghcr.io/aquasecurity/trivy`, `ghcr.io/anchore/grype` | OCI registries (Trivy), `grype.anchore.io` (Grype) |

The official images don't contain the databases: both tools download them when a scan starts.
That download is what failed in a wd2l CI run, when Trivy's mirror returned 404.

The question is how the two travel together, and where scan jobs on each forge (e.g. GitHub,
GitLab) find the databases.

## Decision

* **Use the official images unchanged.** A daily pipeline pulls the latest of each, pins it by
  digest, and saves it into the release.
* **Carry the databases beside the images, not inside them.** The release holds both, with a
  manifest and checksums.
* **On each forge, keep the databases in a directory that runners mount read-only.** Import
  unpacks a release into it and swaps it in whole. Scan jobs run the official images with every
  update and phone-home turned off, and download nothing.

## Options considered

### Option A: official images and a mounted database directory (chosen)

* The images stay exactly as published.
* A database update doesn't mean building an image.
* Scan jobs start at once: nothing to download.
* Needs one runner setting (a read-only volume), and the directory on each runner host (or a
  share).

### Option B: daily images with the databases inside

Official image plus a database layer, tagged by date.

* Pipelines just use the image; the tag pins the tool and its data together.
* Every day produces new images that are no longer the official ones, and the Trivy image grows
  to about 1.2 GB.

### Option C: databases in the forge's registry

Import pushes the databases as OCI artifacts.

* No runner setup, and any number of runners.
* Trivy reads its databases from a registry natively (`--db-repository`), but Grype can't: it
  fetches only over HTTP(S), from a listing, with no way to send credentials. Each Grype job
  would need its own download-and-import step.
* Every scan job downloads about 1.3 GB over the LAN.

### Option D: one custom toolbox image

A UBI 10 minimal or Hummingbird image with both scanners, the scripts and their dependencies.

* Only Docker on the host.
* It's another image to build, maintain and carry, and the scanners in it lag or need
  separate pins. Once the official images are used directly, there's no need for it.

## Consequences

* **Runner setup:** each runner that scans needs the database directory mounted read-only
  (e.g. GitLab: `volumes = ["/srv/vulndb:/srv/vulndb:ro"]` in the runner's `config.toml`).
* **Several runner hosts:** import on each, or put the directory on a share.
* **Release size:** about 1.5 GB a day, two-thirds of it Trivy's Java index. A flag downloads the
  Java index less often; the release still carries the last copy.
* **The host needs Docker and a shell** (bash, coreutils, curl, tar, gzip) for the scripts. No
  jq or Python.
* **Revisit if** runners can't mount a host directory (e.g. a hosted service), which makes
  Option C the fallback.
