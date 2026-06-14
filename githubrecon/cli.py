"""Command-line interface for GITHUBRECON."""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import Report, Severity, analyze, load_export

_SEV_COLOR = {
    Severity.CRITICAL: "#b71c1c",
    Severity.HIGH: "#e65100",
    Severity.MEDIUM: "#f9a825",
    Severity.LOW: "#1565c0",
    Severity.INFO: "#546e7a",
}


def _render_table(rpt: Report) -> str:
    lines: list[str] = []
    lines.append(f"== {TOOL_NAME} v{TOOL_VERSION} ==")
    lines.append(
        f"Owner: {rpt.owner_login or '<unknown>'} "
        f"({rpt.owner_type or '?'}){' - ' + rpt.owner_name if rpt.owner_name else ''}"
    )
    lines.append(
        f"Repos: {rpt.repo_count}  private: {rpt.private_repo_count}  "
        f"forks: {rpt.fork_count}  contributors: {len(rpt.contributors)}  "
        f"emails: {len(rpt.emails)}"
    )
    counts = rpt.counts_by_severity()
    lines.append(
        "Findings by severity: "
        + "  ".join(f"{s}={counts[s]}" for s in
                    (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO))
    )
    lines.append("")
    if not rpt.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    hdr = f"{'SEVERITY':<9} {'RULE':<18} {'REPO':<22} LOCATION / EVIDENCE"
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for f in rpt.findings:
        lines.append(
            f"{f.severity:<9} {f.rule_id:<18} {f.repo[:22]:<22} "
            f"{f.location}  [{f.evidence}]"
        )
    return "\n".join(lines)


def _render_html(rpt: Report) -> str:
    counts = rpt.counts_by_severity()
    e = html.escape

    def chip(sev: str) -> str:
        return (f'<span style="background:{_SEV_COLOR[sev]};color:#fff;'
                f'padding:2px 8px;border-radius:10px;font-size:12px;'
                f'font-weight:600">{sev.upper()} {counts[sev]}</span>')

    rows = []
    for f in rpt.findings:
        rows.append(
            f'<tr>'
            f'<td><span style="color:{_SEV_COLOR.get(f.severity, "#000")};'
            f'font-weight:700">{e(f.severity.upper())}</span></td>'
            f'<td><code>{e(f.rule_id)}</code></td>'
            f'<td>{e(f.title)}</td>'
            f'<td>{e(f.repo)}</td>'
            f'<td><code>{e(f.location)}</code></td>'
            f'<td><code>{e(f.evidence)}</code></td>'
            f'</tr>'
        )
    findings_html = "\n".join(rows) or (
        '<tr><td colspan="6" style="text-align:center;color:#888">'
        'No findings</td></tr>'
    )

    contribs = ", ".join(e(c) for c in rpt.contributors) or "—"
    emails = ", ".join(e(m) for m in rpt.emails) or "—"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report — {e(rpt.owner_login)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   margin:0;background:#f4f6f8;color:#1a2027}}
 .wrap{{max-width:1100px;margin:0 auto;padding:24px}}
 header{{background:#0d1b2a;color:#fff;padding:24px;border-radius:10px}}
 header h1{{margin:0 0 4px;font-size:22px}}
 header .sub{{opacity:.8;font-size:14px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}}
 .card{{background:#fff;border-radius:10px;padding:14px 18px;flex:1;min-width:120px;
   box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .card .n{{font-size:26px;font-weight:700}}
 .card .l{{font-size:12px;color:#667}}
 .chips{{margin:10px 0 18px;display:flex;gap:8px;flex-wrap:wrap}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
   overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #eef1f4;font-size:13px}}
 th{{background:#eef2f6;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#556}}
 tr:hover td{{background:#fafbfc}}
 code{{background:#f0f2f5;padding:1px 5px;border-radius:4px;font-size:12px}}
 .section{{margin-top:24px}}
 .section h2{{font-size:15px;margin:0 0 8px}}
 .foot{{margin:24px 0;color:#889;font-size:12px}}
</style></head><body><div class="wrap">
<header>
 <h1>{e(TOOL_NAME)} — GitHub footprint &amp; leaked-secret report</h1>
 <div class="sub">Owner: <b>{e(rpt.owner_login or "unknown")}</b>
  ({e(rpt.owner_type or "?")}){' &middot; ' + e(rpt.owner_name) if rpt.owner_name else ''}
  &middot; v{TOOL_VERSION}</div>
</header>
<div class="cards">
 <div class="card"><div class="n">{rpt.repo_count}</div><div class="l">Repositories</div></div>
 <div class="card"><div class="n">{rpt.private_repo_count}</div><div class="l">Private</div></div>
 <div class="card"><div class="n">{rpt.fork_count}</div><div class="l">Forks</div></div>
 <div class="card"><div class="n">{len(rpt.contributors)}</div><div class="l">Contributors</div></div>
 <div class="card"><div class="n">{len(rpt.findings)}</div><div class="l">Findings</div></div>
</div>
<div class="chips">{chip(Severity.CRITICAL)}{chip(Severity.HIGH)}{chip(Severity.MEDIUM)}{chip(Severity.LOW)}{chip(Severity.INFO)}</div>
<table>
 <thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Repo</th>
  <th>Location</th><th>Evidence</th></tr></thead>
 <tbody>
{findings_html}
 </tbody>
</table>
<div class="section"><h2>Footprint — contributors</h2><div>{contribs}</div></div>
<div class="section"><h2>Footprint — emails</h2><div>{emails}</div></div>
<div class="foot">Defensive OSINT report generated from a GitHub API export.
 Secrets are masked. Rotate any exposed credential immediately.</div>
</div></body></html>"""


def _write_output(text: str, out_path: str | None) -> None:
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            sys.stderr.write(f"error: cannot write output file: {exc}\n")
            raise
    else:
        sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Map a GitHub user/org footprint and leaked-secret surface "
                    "from an API export (defensive OSINT / forensics).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="analyze a GitHub API export file")
    scan.add_argument("export", help="path to GitHub API export JSON")
    scan.add_argument("--format", choices=("table", "json", "html"),
                      default="table", help="output format")
    scan.add_argument("-o", "--output", help="write report to file instead of stdout")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "any"),
                      default="any",
                      help="minimum severity that triggers a non-zero exit")
    return p


def _max_severity_rank(rpt: Report) -> int:
    return max((Severity.rank(f.severity) for f in rpt.findings), default=-1)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        export = load_export(args.export)
    except FileNotFoundError:
        sys.stderr.write(f"error: export not found: {args.export}\n")
        return 2
    except PermissionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: invalid export: {exc}\n")
        return 2

    rpt = analyze(export)

    try:
        if args.format == "json":
            _write_output(json.dumps(rpt.to_dict(), indent=2), args.output)
        elif args.format == "html":
            _write_output(_render_html(rpt), args.output)
        else:
            _write_output(_render_table(rpt), args.output)
    except OSError:
        return 2

    if args.output:
        sys.stderr.write(f"report written to {args.output}\n")

    # Exit code: non-zero when findings at/above the threshold exist.
    thresholds = {
        "critical": Severity.rank(Severity.CRITICAL),
        "high": Severity.rank(Severity.HIGH),
        "medium": Severity.rank(Severity.MEDIUM),
        "low": Severity.rank(Severity.LOW),
        "any": 0,
    }
    if _max_severity_rank(rpt) >= thresholds[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
