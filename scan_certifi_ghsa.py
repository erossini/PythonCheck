#!/usr/bin/env python3
"""
Scan GitHub organizations for certifi pins affected by GHSA-6q48-6c7w-9gw2.

eMudhra intermediate CA private keys were disclosed as compromised and revoked,
and the emSign root CA was removed from certifi. Clients that still trust it
are open to TLS man-in-the-middle attacks, including against python.org and
pypi.org. Guidance:
https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576

Vulnerable: certifi < 2026.10.18
Fix:        certifi >= 2026.10.19 (recommended; restores unaffected emSign roots)

To check the TLS chains of your servers and endpoints, use
https://github.com/erossini/SSLDomainCheck

Supported file formats (default branch only):
  - requirements.txt / requirements-dev.txt at any depth
      (pip / uv / pip-tools compiled)
  - base.txt, prod.txt, production.txt, dev.txt, development.txt, common.txt,
    local.txt inside a requirements/ directory
  - uv.lock / poetry.lock  (TOML [[package]] blocks)
  - Pipfile.lock           (JSON)

Not checked: pyproject.toml, setup.py/setup.cfg, requirements.in, Conda files,
Dockerfiles, pip's vendored certifi, uv and CPython versions. A clean report
does not mean an organization is unaffected; see README.md.

Outputs:
  - Console: ASCII table sorted vulnerable-first
  - File:    certifi_scan.md by default (Markdown with clickable links)

Usage:
  python scan_certifi_ghsa.py --orgs your-organization
  python scan_certifi_ghsa.py --orgs org-one,org-two
  python scan_certifi_ghsa.py --orgs your-organization --out report.md

Requirements:
  - Python 3.9+
  - packaging   (pip install packaging)
  - gh CLI, authenticated (gh auth login) with read access to every repo to
    scan; private repos need the `repo` scope
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    sys.exit("packaging not found – install it with: pip install packaging")

# ── config ────────────────────────────────────────────────────────────────────

# First version that removes all compromised roots.
# 2026.10.19 restores unaffected emSign roots; both are considered fixed.
FIXED_VERSION = Version("2026.10.18")

# Seconds to sleep between code-search API requests (secondary rate limit: ~30/min).
SEARCH_SLEEP_S: float = 2.5

# ── search configs ────────────────────────────────────────────────────────────
#
# Each entry is (filename, path_qualifier, parser_name) where:
#   filename       – used in the GitHub `filename:` search qualifier
#   path_qualifier – used in `path:` qualifier to narrow to a subdirectory,
#                    or None to search all paths
#   parser_name    – selects the certifi extraction logic for that file format

@dataclass(frozen=True)
class SearchConfig:
    filename: str
    path: Optional[str]   # None → any path; "requirements" → inside requirements/ dirs
    parser: str           # "requirements" | "lock" | "pipfile"

SEARCH_CONFIGS: list[SearchConfig] = [
    # ── pip / uv / pip-tools compiled files ──────────────────────────────────
    # filename: matches at any directory depth, so subdirectory files are found.
    SearchConfig("requirements.txt",     None,           "requirements"),
    SearchConfig("requirements-dev.txt", None,           "requirements"),
    # Split requirements files inside a requirements/ subdirectory
    SearchConfig("base.txt",             "requirements", "requirements"),
    SearchConfig("production.txt",       "requirements", "requirements"),
    SearchConfig("prod.txt",             "requirements", "requirements"),
    SearchConfig("dev.txt",              "requirements", "requirements"),
    SearchConfig("development.txt",      "requirements", "requirements"),
    SearchConfig("common.txt",           "requirements", "requirements"),
    SearchConfig("local.txt",            "requirements", "requirements"),
    # ── lock files ────────────────────────────────────────────────────────────
    SearchConfig("uv.lock",              None,           "lock"),
    SearchConfig("poetry.lock",          None,           "lock"),
    SearchConfig("Pipfile.lock",         None,           "pipfile"),
]

# ── status ordering / display ─────────────────────────────────────────────────

_STATUS_ORDER: dict[str, int] = {
    "VULNERABLE":     0,
    "CHECK MANUALLY": 1,
    "UNKNOWN":        2,
    "FIXED":          3,
    "NOT PINNED":     4,
}
_STATUS_ICON: dict[str, str] = {
    "VULNERABLE":     "❌",
    "FIXED":          "✅",
    "NOT PINNED":     "⚠️ ",
    "CHECK MANUALLY": "🔍",
    "UNKNOWN":        "❓",
}

# ── data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    org: str
    repo: str
    file: str
    certifi_version: str
    status: str
    repo_url: str
    file_url: str

    @property
    def _sort_key(self) -> tuple:
        return (_STATUS_ORDER.get(self.status, 99), self.org, self.repo, self.file)


# ── GitHub helpers ────────────────────────────────────────────────────────────

def _gh(args: list[str]) -> Optional[str]:
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def search_code(org: str, cfg: SearchConfig) -> list[dict]:
    """Return code-search results for *cfg* in *org*. Each item: {repo, path, file_url}."""
    query = f"certifi+filename:{cfg.filename}+org:{org}"
    if cfg.path:
        query += f"+path:{cfg.path}"
    jq_filter = ".items[] | {repo: .repository.full_name, path: .path, file_url: .html_url}"
    out = _gh(["api", "--paginate", "--jq", jq_filter,
                f"/search/code?q={query}&per_page=100"])
    if not out:
        return []
    items: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return items


def fetch_file(org: str, repo: str, path: str) -> Optional[str]:
    """Fetch the current default-branch content of a file; returns decoded text or None."""
    out = _gh(["api", f"/repos/{org}/{repo}/contents/{path}"])
    if not out:
        return None
    try:
        data = json.loads(out)
        if data.get("type") != "file":
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except (json.JSONDecodeError, KeyError, Exception):
        return None


# ── parsers ───────────────────────────────────────────────────────────────────

def _classify(version_str: str) -> str:
    try:
        return "VULNERABLE" if Version(version_str) < FIXED_VERSION else "FIXED"
    except InvalidVersion:
        return "UNKNOWN"


# pip / uv / pip-tools compiled requirements files
# Line format:  certifi==2026.10.19
_REQ_PIN = re.compile(r"^certifi==(\S+)", re.MULTILINE | re.IGNORECASE)
_REQ_CONSTRAINT = re.compile(r"^certifi\s*[><=!~]", re.MULTILINE | re.IGNORECASE)

def parse_requirements(content: str) -> tuple[str, str]:
    pin = _REQ_PIN.search(content)
    if pin:
        v = pin.group(1).rstrip(",;")
        return v, _classify(v)
    if _REQ_CONSTRAINT.search(content):
        return "range/constraint", "CHECK MANUALLY"
    return "—", "NOT PINNED"


# uv.lock / poetry.lock  (TOML [[package]] block format)
# Block example:
#   [[package]]
#   name = "certifi"
#   version = "2026.10.19"
def parse_lock(content: str) -> tuple[str, str]:
    # Split on [[package]] so each chunk is one package's attributes.
    for block in re.split(r"\[\[package\]\]", content):
        if re.search(r'name\s*=\s*["\']certifi["\']', block, re.IGNORECASE):
            m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', block)
            if m:
                v = m.group(1)
                return v, _classify(v)
    return "—", "NOT PINNED"


# Pipfile.lock  (JSON: {"default": {"certifi": {"version": "==2024.7.4"}}})
def parse_pipfile_lock(content: str) -> tuple[str, str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return "—", "UNKNOWN"
    for section in ("default", "develop"):
        entry = data.get(section, {}).get("certifi", {})
        if entry:
            raw = entry.get("version", "")
            v = raw.lstrip("=")   # strip leading "==" from "==2024.7.4"
            if v:
                return v, _classify(v)
    return "—", "NOT PINNED"


_PARSERS: dict[str, Callable[[str], tuple[str, str]]] = {
    "requirements": parse_requirements,
    "lock":         parse_lock,
    "pipfile":      parse_pipfile_lock,
}


# ── scanner ───────────────────────────────────────────────────────────────────

def scan(orgs: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()   # (org, repo, file_path)

    for org in orgs:
        print(f"\n── {org} ──")
        for cfg in SEARCH_CONFIGS:
            label = f"{cfg.filename}" + (f"  (in {cfg.path}/)" if cfg.path else "")
            print(f"  {label:<48}", end="", flush=True)
            items = search_code(org, cfg)
            print(f"{len(items):>3} match(es)")
            time.sleep(SEARCH_SLEEP_S)

            parser = _PARSERS[cfg.parser]

            for item in items:
                full_name: str = item["repo"]
                repo_name = full_name.split("/", 1)[1]
                file_path: str = item["path"]
                key = (org, repo_name, file_path)
                if key in seen:
                    continue
                seen.add(key)

                content = fetch_file(org, repo_name, file_path)
                if content is None:
                    version, status = "—", "UNKNOWN"
                else:
                    version, status = parser(content)

                repo_url = f"https://github.com/{full_name}"
                findings.append(Finding(
                    org=org,
                    repo=repo_name,
                    file=file_path,
                    certifi_version=version,
                    status=status,
                    repo_url=repo_url,
                    file_url=f"{repo_url}/blob/HEAD/{file_path}",
                ))

    return sorted(findings, key=lambda f: f._sort_key)


# ── output ────────────────────────────────────────────────────────────────────

def print_table(findings: list[Finding]) -> None:
    if not findings:
        print("\nNo certifi references found in any scanned files.")
        return

    headers = ["Org", "Repository", "File", "certifi", "Status"]
    rows = [
        [f.org, f.repo, f.file, f.certifi_version,
         f"{_STATUS_ICON.get(f.status, '')} {f.status}"]
        for f in findings
    ]
    widths = [
        max(len(h), max(len(row[i]) for row in rows))
        for i, h in enumerate(headers)
    ]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    fmt = "| " + " | ".join(f"{{:<{w}}}" for w in widths) + " |"

    print("\n" + sep)
    print(fmt.format(*headers))
    print(sep)
    for row in rows:
        print(fmt.format(*row))
    print(sep)

    total_repos = len({(f.org, f.repo) for f in findings})
    print(f"\n{len(findings)} file(s) in {total_repos} repo(s):")
    for status, icon in _STATUS_ICON.items():
        n = sum(1 for f in findings if f.status == status)
        if n:
            print(f"  {icon} {status:<18} {n}")


def write_markdown(findings: list[Finding], orgs: list[str], out_path: str) -> None:
    vulnerable = [f for f in findings if f.status == "VULNERABLE"]

    with open(out_path, "w") as fh:
        fh.write("# GHSA-6q48-6c7w-9gw2 Certifi Vulnerability Scan\n\n")
        fh.write("| | |\n|---|---|\n")
        fh.write("| **Advisory** | GHSA-6q48-6c7w-9gw2 |\n")
        fh.write("| **Impact** | On-path attacker can forge TLS certs trusted by `requests`, `urllib3`, `pip` |\n")
        fh.write("| **Vulnerable** | `certifi < 2026.10.18` |\n")
        fh.write("| **Fix** | `certifi >= 2026.10.19` |\n")
        fh.write(f"| **Orgs scanned** | {', '.join(f'`{o}`' for o in orgs)} |\n\n")

        fh.write("## Results\n\n")
        fh.write("| Org | Repository | File | certifi version | Status |\n")
        fh.write("|-----|-----------|------|----------------|--------|\n")
        for fi in findings:
            icon = _STATUS_ICON.get(fi.status, "")
            fh.write(
                f"| {fi.org} "
                f"| [{fi.repo}]({fi.repo_url}) "
                f"| [{fi.file}]({fi.file_url}) "
                f"| `{fi.certifi_version}` "
                f"| {icon} {fi.status} |\n"
            )

        if vulnerable:
            fh.write("\n## Action required\n\n")
            fh.write(
                "The following repos pin a vulnerable certifi version "
                "and need a dependency update:\n\n"
            )
            for fi in vulnerable:
                fh.write(
                    f"- [ ] [{fi.org}/{fi.repo}]({fi.repo_url}) — "
                    f"[`{fi.file}`]({fi.file_url}) pins "
                    f"`certifi=={fi.certifi_version}`\n"
                )
        else:
            fh.write("\n> No repositories with a pinned vulnerable certifi version found.\n")

    print(f"\nMarkdown report → {out_path}")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan GitHub orgs for GHSA-6q48-6c7w-9gw2 (certifi vulnerability)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--orgs",
        required=True,
        help="Comma-separated GitHub orgs to scan (required)",
    )
    parser.add_argument(
        "--out",
        default="certifi_scan.md",
        help="Output Markdown file path (default: certifi_scan.md)",
    )
    args = parser.parse_args()

    orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    if not orgs:
        parser.error("--orgs must name at least one organization")

    print("Advisory:  GHSA-6q48-6c7w-9gw2")
    print(f"Fix:       certifi >= {FIXED_VERSION}")
    print(f"Orgs:      {', '.join(orgs)}")
    print(f"Formats:   requirements.txt, uv.lock, poetry.lock, Pipfile.lock")

    findings = scan(orgs)
    print_table(findings)
    write_markdown(findings, orgs, args.out)


if __name__ == "__main__":
    main()
