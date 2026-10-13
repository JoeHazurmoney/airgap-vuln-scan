# airgap-vuln-scan

Scan container images with Trivy and Grype where there's no internet: the scanners and their
vulnerability databases are prepared on a connected system, carried across the gap, and checked
for age before every scan.

> **Status:** design. The [spec](docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md)
> is under review; the scripts and the CI that proves them come next.

## Problem

Vulnerability scanners download their databases when a scan starts.

* **A system with no internet can't.** The official Trivy and Grype images hold only the scanner,
  so pulling the latest images isn't enough.
* **Even a connected pipeline depends on the database host.** A CI run in another project failed
  when Trivy's database mirror returned 404, though nothing about the image under test had
  changed.
* **Databases go stale quietly.** Once they're carried by hand, nothing says when they're too old
  to trust.

## Approach

```mermaid
flowchart LR
  subgraph NET["Internet"]
    IMG["Official images<br/>trivy:latest · grype:debug"]
    DBS["Vulnerability databases<br/>trivy-db · trivy-java-db · Grype DB"]
  end
  subgraph CON["Connected forge (e.g. GitHub, GitLab)"]
    FETCH["Daily pipeline<br/>fetch → package → import"]
    CDIR[("Database directory")]
    CSCAN["Scan jobs<br/>age check → scan"]
    REL["Release scanners-YYYY-MM-DD<br/>images · databases<br/>MANIFEST · SHA256SUMS"]
  end
  subgraph GAP["Physical air gap"]
    MEDIA[/Removable media/]
  end
  subgraph DIS["Disconnected forge (e.g. GitHub, GitLab)"]
    IMPORT["Import<br/>verify, load, push, unpack"]
    REG[("Registry")]
    DDIR[("Database directory")]
    DSCAN["Scan jobs<br/>age check → scan"]
  end
  IMG --> FETCH
  DBS --> FETCH
  FETCH --> REL
  FETCH --> CDIR --> CSCAN
  REL --> MEDIA --> IMPORT
  IMPORT --> REG --> DSCAN
  IMPORT --> DDIR --> DSCAN
```

1. **Fetch, once a day, on the connected forge.** Pull the latest official Trivy and Grype images
   and pin them by digest. Download Trivy's database, its Java index and Grype's database.
2. **Package a release.** One dated directory: the two images, the three databases, a manifest
   (versions, digests, build times) and `SHA256SUMS`. About 1.5 GB.
3. **Carry it** across the gap on removable media.
4. **Import it.** Verify every checksum first, and refuse the release if any file changed. Load
   the images into the forge's registry. Unpack the databases into a directory the runners mount
   read-only, and swap it in whole. The connected forge imports its own release the same way.
5. **Scan.** First check each database's age: past 7 days, log a warning naming it, and carry on.
   Then run both scanners with networking disabled and every download turned off.

How it fits together is in [docs/architecture.md](docs/architecture.md), and why it's built
this way is in [ADR-0001](docs/decisions/0001-scanner-images-and-databases.md). Until the build,
the commands and settings are in the
[spec](docs/superpowers/specs/2026-10-13-airgap-vuln-scan-design.md).

**About Trivy's Java database.** It isn't vulnerability data: it's an index that tells Trivy what
a JAR file is, for JARs that don't say so themselves. Trivy won't scan an image containing JARs
offline without it, so every release includes it. At 983 MB it's most of the release, and an old
copy misses no vulnerabilities, so you can download it less often
(`--java-db-refresh-days N`) and give it a longer age limit (`MAX_JAVA_DB_AGE_DAYS`).

## Result

*Filled in after the build, from the CI run that proves it:* a scan with no network access, the
stale-database warning with the job still passing, no warning when the databases are fresh, a
tampered release refused, and the sizes and run times.
