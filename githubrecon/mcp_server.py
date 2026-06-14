"""GITHUBRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-githubrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-githubrecon[mcp]'")
        return 1
    app = FastMCP("githubrecon")

    from githubrecon.core import load_export, analyze
    import json as _json

    @app.tool()
    def githubrecon_scan(target: str) -> str:
        """Map a GitHub user/org footprint & leaked-secret surface from API exports. Returns JSON findings."""
        try:
            export = load_export(target)
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            return _json.dumps({"error": str(exc)})
        rpt = analyze(export)
        return _json.dumps(rpt.to_dict(), indent=2)

    app.run()
    return 0
