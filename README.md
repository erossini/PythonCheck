# Certification GHSA scanner

`scan_certifi_ghsa.py` searches one or more GitHub organizations for Python dependency files that pin a vulnerable version of [`certifi`](https://pypi.org/project/certifi/), and writes a report of what it finds.

It targets advisory [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2), which covers the eMudhra / emSign CA certificate incident.

## Background

In October 2026, the private keys of eMudhra intermediate CAs were disclosed as compromised and the intermediates were revoked. To remove that trust, the emSign root CA was taken out of CA bundles such as `certifi`. Any client that still trusts it is open to man-in-the-middle attacks on TLS, including connections to `python.org` and `pypi.org`.

The Python Software Foundation's official guidance is in this thread:
[Information for Python users regarding eMudhra / emSign CA certificate security incident](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)

In summary:

| Component | Fixed in |
|---|---|
| `certifi` | `2026.10.18` per the advisory. `2026.10.19` is recommended because it restores the emSign roots that were not affected |
| `pip` | `26.2.2`. pip always loads its vendored `certifi`, so a patched OS trust store is not enough |
| `uv` | `0.13.6` ([GHSA-hq85-5cpj-mr62](https://github.com/advisories/GHSA-hq85-5cpj-mr62)) |
| CPython | `3.15.2`, `3.14.10`, `3.13.18`, `3.12.16`, `3.11.18`. These reject the compromised intermediates whatever `certifi` contains. 3.10 and older are end-of-life and will not be fixed |

The thread also lists fixed versions of virtualenv, pipx, pipenv, PDM, Hatch, conda, pixi, cibuildwheel, the manylinux images, `gh-action-pypi-publish` and the Docker `python` images. It includes the checksum-verified command for upgrading pip safely, so read it before upgrading.

### Related tool: SSLDomainCheck

The incident needs two kinds of work:

1. **Client side.** Find and upgrade code that trusts the compromised certificates. This repository covers the part of that work that applies to `certifi` pins in your GitHub repositories.
2. **Server side.** Find services you run or call whose TLS chain still goes through an eMudhra / emSign CA. Use [**SSLDomainCheck**](https://github.com/erossini/SSLDomainCheck) for this. It has PowerShell and bash scripts that check the certificate chain of every URL in a list and flag any chain involving eMudhra / emSign.

## Requirements

- Python 3.9 or later
- [`packaging`](https://pypi.org/project/packaging/) (`pip install packaging`)
- The [GitHub CLI](https://cli.github.com/), authenticated with `gh auth login`. The token needs read access to every repository you want to scan. Private repositories need the `repo` scope.

## Usage

`--orgs` is required. Separate multiple organizations with commas.

```bash
python scan_certifi_ghsa.py --orgs your-organization
python scan_certifi_ghsa.py --orgs org-one,org-two
python scan_certifi_ghsa.py --orgs your-organization --out report.md
```

| Option | Required | Default | Description |
|---|---|---|---|
| `--orgs` | yes | none | Comma-separated GitHub organizations to scan |
| `--out` | no | `certifi_scan.md` | Path of the Markdown report |

## What it scans

For each organization, the script runs a GitHub code search for files that mention `certifi`, fetches each match from the repository's default branch, and extracts the pinned version.

| Format | Files |
|---|---|
| pip / uv / pip-tools requirements | `requirements.txt` and `requirements-dev.txt` at any depth. `base.txt`, `prod.txt`, `production.txt`, `dev.txt`, `development.txt`, `common.txt` and `local.txt` inside a `requirements/` directory |
| TOML lock files | `uv.lock`, `poetry.lock` |
| Pipenv | `Pipfile.lock` |

## Output

The script prints a table to the console with the most urgent results first. It also writes a Markdown report with links to each repository and file, and a checklist of the repositories that need an update.

| Status | Meaning |
|---|---|
| ❌ `VULNERABLE` | Pins `certifi` below `2026.10.18` |
| 🔍 `CHECK MANUALLY` | Uses a range or constraint (`>=`, `~=`, …) rather than an exact pin. The installed version depends on when the environment was built |
| ❓ `UNKNOWN` | The file could not be fetched or parsed, or the version string is not valid |
| ✅ `FIXED` | Pins `certifi` `2026.10.18` or later |
| ⚠️ `NOT PINNED` | The file mentions `certifi` but no version could be extracted |

## Limitations

A clean report does **not** mean an organization is unaffected. The script checks only one part of the problem:

- **Default branch only.** GitHub code search indexes only the default branch, so other branches and tags are not checked.
- **Pinned files only.** It does not read `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements.in`, Conda environment files or Dockerfiles. A `certifi` installed as a transitive dependency without a lock file is not visible.
- **No pip, uv or Python versions.** pip's vendored `certifi`, the uv version and the CPython version in your images and CI runners all matter (see [Background](#background)), and none of them are checked.
- **Code search coverage.** GitHub code search can miss files, for example very large files, forks and archived repositories. It also has a secondary rate limit, so the script waits 2.5 s between searches and large organizations take a while.

Use the report to find repositories to fix, not as proof that an organization is safe. To be confident, also upgrade pip, Python and your base images, and check your endpoints with [SSLDomainCheck](https://github.com/erossini/SSLDomainCheck).
