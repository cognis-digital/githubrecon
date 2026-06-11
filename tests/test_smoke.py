"""Smoke tests for GITHUBRECON. No network. Run with: python -m pytest -q
   (also runnable directly: python tests/test_smoke.py)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from githubrecon import TOOL_NAME, TOOL_VERSION, analyze, load_export  # noqa: E402
from githubrecon.cli import main, _render_html  # noqa: E402
from githubrecon.core import Severity  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "export.json")


# Built at runtime so the literal Stripe key never appears verbatim in source
# (keeps push-protection / secret scanners quiet) while still exercising the
# stripe_live rule against the assembled file content.
SAMPLE_STRIPE = "sk_" + "live_" + ("0" * 24) + "RECON"


def _sample():
    return {
        "owner": {"login": "acme", "type": "Organization", "name": "ACME"},
        "repos": [{
            "full_name": "acme/app",
            "private": False,
            "contributors": [{"login": "alice", "email": "alice@acme.io"}],
            "files": [
                {"path": ".env",
                 "content": "STRIPE=" + SAMPLE_STRIPE + "\n"},
                {"path": "ok.py",
                 "content": "api_key = \"your_api_key_here\"\n"},
            ],
        }],
    }


def test_metadata():
    assert TOOL_NAME == "githubrecon"
    assert TOOL_VERSION.count(".") == 2


def test_analyze_detects_secret_and_footprint():
    rpt = analyze(_sample())
    assert rpt.repo_count == 1
    assert "alice" in rpt.contributors
    assert "alice@acme.io" in rpt.emails
    ids = {f.rule_id for f in rpt.findings}
    assert "stripe_live" in ids
    assert "risky_filename" in ids  # .env committed


def test_placeholder_suppressed():
    rpt = analyze(_sample())
    for f in rpt.findings:
        assert "your_api_key_here" not in f.evidence


def test_secret_is_masked():
    rpt = analyze(_sample())
    stripe = [f for f in rpt.findings if f.rule_id == "stripe_live"][0]
    assert "..." in stripe.evidence
    assert SAMPLE_STRIPE not in stripe.evidence


def test_severity_ordering():
    rpt = analyze(_sample())
    ranks = [Severity.rank(f.severity) for f in rpt.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_html_is_self_contained():
    rpt = analyze(_sample())
    out = _render_html(rpt)
    assert out.startswith("<!DOCTYPE html>")
    assert "<style>" in out
    assert "src=" not in out
    assert "http://" not in out and "https://" not in out


def test_demo_export_loads_and_scans():
    export = load_export(DEMO)
    rpt = analyze(export)
    assert rpt.owner_login == "acme-labs"
    ids = {f.rule_id for f in rpt.findings}
    assert "private_key" in ids
    assert "stale_public_repo" in ids
    assert rpt.private_repo_count == 1


def test_cli_json_and_exit_code():
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1  # findings exist


def test_cli_writes_html():
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "r.html")
        rc = main(["scan", DEMO, "--format", "html", "-o", out])
        assert rc == 1
        with open(out, encoding="utf-8") as fh:
            assert "<!DOCTYPE html>" in fh.read()


def test_cli_fail_on_threshold():
    rc = main(["scan", DEMO, "--fail-on", "critical"])
    assert rc == 1  # demo has critical findings


def test_missing_export_returns_2():
    rc = main(["scan", os.path.join(tempfile.gettempdir(), "nope_missing.json")])
    assert rc == 2


def test_no_command_returns_2():
    assert main([]) == 2


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
