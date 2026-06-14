"""Core engine for GITHUBRECON.

Consumes a GitHub API export (JSON) and produces a footprint + leaked-secret
report. The export schema is intentionally close to the real GitHub REST API so
exports captured with `gh api` / curl can be fed in directly.

Expected export shape (all keys optional, extras ignored)::

    {
      "owner": {"login": "acme", "type": "Organization", "name": "ACME Inc"},
      "repos": [
        {
          "full_name": "acme/widgets",
          "private": false,
          "fork": false,
          "default_branch": "main",
          "pushed_at": "2026-01-02T00:00:00Z",
          "contributors": [{"login": "alice", "email": "alice@acme.com"}],
          "files": [
            {"path": ".env", "content": "AWS_SECRET=..."}
          ]
        }
      ]
    }
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    _ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls._ORDER.get(sev, 0)


# Each rule: (id, severity, human label, compiled regex).
# Patterns target high-signal credential formats so false positives stay low.
_RAW_RULES: list[tuple[str, str, str, str]] = [
    ("aws_access_key", Severity.CRITICAL, "AWS Access Key ID",
     r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ("aws_secret_key", Severity.CRITICAL, "AWS Secret Access Key",
     r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ("github_pat", Severity.CRITICAL, "GitHub Personal Access Token",
     r"\b(gh[pousr]_[A-Za-z0-9]{30,255})\b"),
    ("github_oauth", Severity.CRITICAL, "GitHub OAuth/Refresh Token",
     r"\b(gho_[A-Za-z0-9]{36})\b"),
    ("slack_token", Severity.HIGH, "Slack Token",
     r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    ("google_api_key", Severity.HIGH, "Google API Key",
     r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ("stripe_live", Severity.CRITICAL, "Stripe Live Secret Key",
     r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    ("stripe_test", Severity.LOW, "Stripe Test Secret Key",
     r"\b(sk_test_[0-9a-zA-Z]{24,})\b"),
    ("private_key", Severity.CRITICAL, "Private Key Block",
     r"(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----)"),
    ("jwt", Severity.MEDIUM, "JSON Web Token",
     r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
    ("npm_token", Severity.HIGH, "npm Access Token",
     r"\b(npm_[A-Za-z0-9]{36})\b"),
    ("twilio_key", Severity.HIGH, "Twilio API Key",
     r"\b(SK[0-9a-fA-F]{32})\b"),
    ("generic_secret", Severity.MEDIUM, "Generic Hardcoded Secret",
     r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*"
     r"['\"]([A-Za-z0-9!@#$%^&*()_+\-=/]{12,64})['\"]"),
    ("private_email", Severity.LOW, "Email Address (footprint)",
     r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"),
]

SECRET_RULES = [(rid, sev, label, re.compile(pat))
                for rid, sev, label, pat in _RAW_RULES]

# Filenames that are high-risk if present at all (config/credential dumps).
_RISKY_FILENAMES = {
    ".env": Severity.HIGH,
    ".npmrc": Severity.MEDIUM,
    ".pypirc": Severity.MEDIUM,
    "id_rsa": Severity.CRITICAL,
    "id_dsa": Severity.CRITICAL,
    "credentials": Severity.HIGH,
    ".aws/credentials": Severity.CRITICAL,
    "secrets.yml": Severity.HIGH,
    "secrets.yaml": Severity.HIGH,
    "wp-config.php": Severity.MEDIUM,
}

# Values that look like secrets but are placeholders — suppress noise.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?\w+|example|changeme|xxxx+|placeholder|<[^>]+>|\.\.\.|dummy|sample)"
)


def _mask(value: str) -> str:
    """Mask a secret so the report is safe to share."""
    v = value.strip()
    if len(v) <= 8:
        return v[:2] + "***"
    return f"{v[:4]}...{v[-4:]} (len {len(v)})"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    repo: str
    location: str
    evidence: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    owner_login: str = ""
    owner_type: str = ""
    owner_name: str = ""
    repo_count: int = 0
    private_repo_count: int = 0
    fork_count: int = 0
    contributors: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def secret_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.rule_id != "private_email"]

    def counts_by_severity(self) -> dict[str, int]:
        out = {s: 0 for s in (Severity.CRITICAL, Severity.HIGH,
                              Severity.MEDIUM, Severity.LOW, Severity.INFO)}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": {
                "login": self.owner_login,
                "type": self.owner_type,
                "name": self.owner_name,
            },
            "summary": {
                "repos": self.repo_count,
                "private_repos": self.private_repo_count,
                "forks": self.fork_count,
                "contributors": len(self.contributors),
                "emails": len(self.emails),
                "findings": len(self.findings),
                "severity_counts": self.counts_by_severity(),
            },
            "contributors": self.contributors,
            "emails": self.emails,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_export(path: str) -> dict[str, Any]:
    """Load and minimally validate a GitHub API export file."""
    if not path or not str(path).strip():
        raise ValueError("export path must not be empty")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except PermissionError as exc:
        raise PermissionError(f"permission denied reading export: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("export root must be a JSON object")
    if "repos" not in data or not isinstance(data["repos"], list):
        raise ValueError("export must contain a 'repos' array")
    return data


def _scan_content(repo: str, location: str, content: str) -> Iterable[Finding]:
    """Run every secret rule over a file's content."""
    seen: set[tuple[str, str]] = set()
    for rid, sev, label, rx in SECRET_RULES:
        for m in rx.finditer(content):
            value = m.group(1) if m.groups() else m.group(0)
            if _PLACEHOLDER.search(value):
                continue
            key = (rid, value)
            if key in seen:
                continue
            seen.add(key)
            line = content[: m.start()].count("\n") + 1
            yield Finding(
                rule_id=rid,
                severity=sev,
                title=label,
                repo=repo,
                location=f"{location}:{line}",
                evidence=_mask(value),
                detail=f"matched rule {rid}",
            )


def _basename(path: str) -> str:
    return path.replace("\\", "/").split("/")[-1].lower()


def analyze(export: dict[str, Any]) -> Report:
    """Build a footprint + secret report from an export dict."""
    _raw_owner = export.get("owner", {})
    owner = _raw_owner if isinstance(_raw_owner, dict) else {}
    rpt = Report(
        owner_login=str(owner.get("login", "")),
        owner_type=str(owner.get("type", "")),
        owner_name=str(owner.get("name", "")),
    )

    contributors: set[str] = set()
    emails: set[str] = set()
    repos = export.get("repos", [])
    rpt.repo_count = len(repos)

    for repo in repos:
        if not isinstance(repo, dict):
            continue
        full = str(repo.get("full_name") or repo.get("name") or "<unknown>")
        if repo.get("private"):
            rpt.private_repo_count += 1
        if repo.get("fork"):
            rpt.fork_count += 1

        # Footprint: contributors + emails.
        for c in repo.get("contributors", []) or []:
            if isinstance(c, dict):
                if c.get("login"):
                    contributors.add(str(c["login"]))
                if c.get("email"):
                    emails.add(str(c["email"]))
            elif isinstance(c, str):
                contributors.add(c)

        # Stale repo warning (footprint hygiene).
        pushed = repo.get("pushed_at")
        if pushed:
            try:
                dt = datetime.fromisoformat(str(pushed).replace("Z", "+00:00"))
                days = (datetime.now(timezone.utc) - dt).days
                if days > 365 and not repo.get("private") and not repo.get("fork"):
                    rpt.findings.append(Finding(
                        rule_id="stale_public_repo",
                        severity=Severity.INFO,
                        title="Stale public repo",
                        repo=full,
                        location=full,
                        evidence=f"last push {days}d ago",
                        detail="abandoned public repos widen attack surface",
                    ))
            except ValueError:
                pass

        # File scanning.
        for f in repo.get("files", []) or []:
            if not isinstance(f, dict):
                continue
            fpath = str(f.get("path", ""))
            content = f.get("content")
            base = _basename(fpath)
            norm = fpath.replace("\\", "/").lower()

            risky = None
            for name, sev in _RISKY_FILENAMES.items():
                if base == name or norm.endswith(name):
                    risky = sev
                    break
            if risky:
                rpt.findings.append(Finding(
                    rule_id="risky_filename",
                    severity=risky,
                    title="Sensitive file committed",
                    repo=full,
                    location=fpath,
                    evidence=base,
                    detail="credential/config file tracked in source",
                ))

            if isinstance(content, str) and content:
                for finding in _scan_content(full, fpath, content):
                    if finding.rule_id == "private_email":
                        emails.add(finding.evidence)
                    else:
                        rpt.findings.append(finding)

    rpt.contributors = sorted(contributors)
    rpt.emails = sorted(emails)

    # Stable, severity-first ordering.
    rpt.findings.sort(
        key=lambda f: (-Severity.rank(f.severity), f.repo, f.location, f.rule_id)
    )
    return rpt
