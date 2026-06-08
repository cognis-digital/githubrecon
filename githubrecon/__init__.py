"""GITHUBRECON — map a GitHub user/org footprint & leaked-secret surface from API exports.

Defensive OSINT/forensics: analyze JSON exports you obtained from the GitHub API
(repos, contributors, file blobs) to surface a developer/org footprint and any
secrets that have leaked into source you own. No network access, stdlib only.
"""
from .core import (
    Finding,
    Report,
    Severity,
    analyze,
    load_export,
    SECRET_RULES,
)

TOOL_NAME = "githubrecon"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "analyze",
    "load_export",
    "SECRET_RULES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
