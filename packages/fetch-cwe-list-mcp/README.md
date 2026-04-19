# fetch-cwe-list-mcp

> **Experimental:** This package is in alpha (v0.1.0-alpha.0). APIs may change.

MCP (Model Context Protocol) server that exposes the [fetch-cwe-list](https://github.com/alejandrosaenz117/fetch-cwe-list) library as tools for LLM agents like Claude.

## Installation

```bash
npm install -g fetch-cwe-list-mcp
```

Or run directly with npx (no installation needed):

```bash
npx fetch-cwe-list-mcp
```

## Usage

### With Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cwe": {
      "command": "npx",
      "args": ["-y", "fetch-cwe-list-mcp"]
    }
  }
}
```

Then restart Claude Desktop. The CWE tools will be available.

### Run directly

```bash
npx fetch-cwe-list-mcp
```

This starts the stdio-transport server. The protocol is JSON-RPC 2.0.

## Tools

| Tool | Description |
|------|-------------|
| `fetch_cwe_list` | Fetch the full CWE list. Returns count + 5-entry preview. Accepts optional `version` and `cache` parameters. |
| `find_cwe_by_id` | Find a single CWE by its numeric ID string (e.g., `"79"`). Auto-fetches the list. |
| `find_cwe_by_name` | Find all CWEs whose name contains a substring (case-insensitive). Auto-fetches the list. |
| `find_cwe_by_capec` | Find all CWEs mapped to a CAPEC attack pattern ID. Auto-fetches the list. |

All find tools auto-fetch and cache the CWE list on first invocation. Results are cached in memory for 1 hour.

## Dependencies

This package pins exact versions of critical dependencies for supply chain security:
- `@modelcontextprotocol/sdk@1.29.0` — MCP protocol implementation
- `fetch-cwe-list@0.0.12` — Core CWE data library
- `zod@4.3.6` — Input validation

## Development

```bash
# Install workspace dependencies
npm install

# Run unit tests
npm test --workspace=packages/fetch-cwe-list-mcp

# Test with MCP Inspector (interactive browser UI)
npx @modelcontextprotocol/inspector node packages/fetch-cwe-list-mcp/index.js
```

## License

MIT

## Author

[Alejandro Saenz](https://github.com/alejandrosaenz117)
