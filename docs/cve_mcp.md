# Vantix CVE MCP

The Vantix CVE MCP server exposes cached CVE and vulnerability-intel data to MCP clients. It can run embedded in the FastAPI app or as a standalone MCP server.

## Prerequisites

Install project dependencies with the MCP extra from `pyproject.toml`:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Optional live sources require their own API tokens, for example `GITHUB_TOKEN`, `NVD_NIST_API_KEY`, `VULNCHECK_API_TOKEN`, or other source-specific keys. MCP tools work without those tokens against the local cache and configured `SECOPS_CVE_SEARCH_URL`.

## Embedded FastAPI MCP

Use this when the API server should host MCP over HTTP.

```bash
export SECOPS_ENABLE_CVE_MCP=true
export SECOPS_API_TOKEN='change-me'
export SECOPS_CVE_MCP_PATH=/mcp/cve
export SECOPS_CVE_MCP_REQUIRE_TOKEN=true
export SECOPS_CVE_MCP_ALLOWED_ORIGINS='http://127.0.0.1,http://localhost'
bash scripts/secops-api.sh
```

Endpoint:

```text
http://127.0.0.1:8787/mcp/cve
Authorization: Bearer change-me
```

## Standalone MCP

Use stdio for local agent integrations:

```bash
bash scripts/secops-cve-mcp.sh --stdio
```

Use streamable HTTP for a separately managed service:

```bash
bash scripts/secops-cve-mcp.sh --http --host 127.0.0.1 --port 8788
```

## Client Configuration

Generic stdio client entry:

```json
{
  "mcpServers": {
    "vantix-cve": {
      "command": "bash",
      "args": ["/path/to/CTF/scripts/secops-cve-mcp.sh", "--stdio"],
      "env": {
        "SECOPS_REPO_ROOT": "/path/to/CTF",
        "SECOPS_RUNTIME_ROOT": "/home/operator/.local/state/ctf-security-ops/CTF"
      }
    }
  }
}
```

Generic HTTP client entry:

```json
{
  "mcpServers": {
    "vantix-cve-http": {
      "url": "http://127.0.0.1:8787/mcp/cve",
      "headers": {
        "Authorization": "Bearer change-me"
      }
    }
  }
}
```

## Tools

| Tool | Purpose |
| --- | --- |
| `search_cves(vendor, product, limit=20)` | Query the configured cve-search API and enrich with local intel. |
| `search_intel(query, limit=25, sources=null, live_on_miss=false)` | Search cached normalized vulnerability intel. Optional live fetch only runs when requested. |
| `get_cve_intel(cve_id)` | Return cached intel records for one CVE. |
| `recent_intel(days=7, limit=25)` | Return recent prioritized intel from the local cache. |
| `list_intel_sources(include_optional=true)` | List source adapters compiled into the system. |
| `update_intel_source(source="cisa_kev", dry_run=true)` | Fetch one source. Defaults to dry-run to avoid surprise writes. |

## Resources

| Resource | Purpose |
| --- | --- |
| `cve://{cve_id}` | CVE-specific local intel. |
| `cve-intel://recent/{days}` | Recent intel window. |
| `cve-intel://sources` | Available intel sources. |

## Prompts

| Prompt | Purpose |
| --- | --- |
| `prioritize_service_cves(service, version="", target_context="")` | Rank CVE candidates for an observed service. |
| `cve_validation_plan(cve_id, target_context="")` | Produce a safe evidence-oriented validation plan. |

## Security Notes

Keep `SECOPS_CVE_MCP_REQUIRE_TOKEN=true` for hosted HTTP unless the service is bound to an isolated loopback-only environment. Set `SECOPS_CVE_MCP_ALLOWED_ORIGINS` to exact local UI/client origins. Do not expose live update tools to untrusted clients; those tools can trigger external requests and local cache writes when `dry_run=false` or `live_on_miss=true`.

## Troubleshooting

`RuntimeError: Install the MCP extra first` means the `mcp` package is missing. Run `pip install -e .` again inside the active virtual environment.

`401` means the bearer token is missing or wrong. Set `Authorization: Bearer <SECOPS_API_TOKEN>`.

`403` means the HTTP origin is not in `SECOPS_CVE_MCP_ALLOWED_ORIGINS`.

Empty search results usually mean the local cache has not been seeded. Run `update_intel_source` in dry-run first, then repeat with `dry_run=false` for trusted sources.
