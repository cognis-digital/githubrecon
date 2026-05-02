"""GITHUBRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from githubrecon.core import scan, to_json

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

    @app.tool()
    def githubrecon_scan(target: str) -> str:
        """Map a GitHub user/org footprint & leaked-secret surface from API exports. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
