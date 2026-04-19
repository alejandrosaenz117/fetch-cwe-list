'use strict'

const path = require('path')
const sdkPath = path.join(__dirname, '../../node_modules/@modelcontextprotocol/sdk/dist/cjs')
const { McpServer } = require(path.join(sdkPath, 'server/mcp.js'))
const { StdioServerTransport } = require(path.join(sdkPath, 'server/stdio.js'))
const { z } = require('zod')
const fetchCweList = require('fetch-cwe-list')

// Re-export query helpers from fetch-cwe-list
const { findById, findByName, findByCapec, clearCache } = fetchCweList

// Module-level cache so all tools in the same session share the same fetched list
let _cachedList = null

async function getCweList(version, bypassCache = false) {
  if (!bypassCache && _cachedList !== null) {
    return _cachedList
  }
  if (bypassCache) {
    clearCache()
    _cachedList = null
  }
  const list = await fetchCweList(version, { cache: !bypassCache })
  _cachedList = list
  return list
}

// Input schemas (Zod)
const FetchCweListInput = z.object({
  version: z.string().optional(),
  cache: z.boolean().optional().default(true)
})

const FindByIdInput = z.object({
  id: z.string()
})

const FindByNameInput = z.object({
  pattern: z.string()
})

const FindByCapecInput = z.object({
  capec_id: z.string()
})

// Create MCP server
const server = new McpServer({
  name: 'fetch-cwe-list-mcp',
  version: '0.1.0-alpha.0'
})

// Register tools
server.tool(
  'fetch_cwe_list',
  'Fetch the full MITRE CWE list. Returns total count plus the first 5 entries as a preview. Results are cached in memory for 1 hour. Use cache=false to force a fresh download.',
  {
    version: z.string().optional(),
    cache: z.boolean().optional().default(true)
  },
  async (params) => {
    const { version, cache } = FetchCweListInput.parse(params ?? {})
    const list = await getCweList(version, cache === false)
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            total: list.length,
            version: version ?? 'latest',
            preview: list.slice(0, 5).map((cwe) => ({
              ID: cwe.ID,
              Name: cwe.Name,
              Abstraction: cwe.Abstraction,
              Status: cwe.Status,
              Description: cwe.Description.substring(0, 200)
            }))
          }, null, 2)
        }
      ]
    }
  }
)

server.tool(
  'find_cwe_by_id',
  'Find a single CWE entry by its numeric ID. The list is auto-fetched and cached if not already loaded.',
  {
    id: z.string()
  },
  async (params) => {
    const { id } = FindByIdInput.parse(params)
    const list = await getCweList()
    const result = findById(list, id)
    return {
      content: [
        {
          type: 'text',
          text: result
            ? JSON.stringify(result, null, 2)
            : JSON.stringify({ error: `CWE-${id} not found` })
        }
      ]
    }
  }
)

server.tool(
  'find_cwe_by_name',
  'Search CWEs by name substring (case-insensitive). The list is auto-fetched and cached if not already loaded.',
  {
    pattern: z.string()
  },
  async (params) => {
    const { pattern } = FindByNameInput.parse(params)
    const list = await getCweList()
    const results = findByName(list, pattern)
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ count: results.length, results }, null, 2)
        }
      ]
    }
  }
)

server.tool(
  'find_cwe_by_capec',
  'Find all CWEs that map to a given CAPEC attack pattern ID. The list is auto-fetched and cached if not already loaded.',
  {
    capec_id: z.string()
  },
  async (params) => {
    const { capec_id } = FindByCapecInput.parse(params)
    const list = await getCweList()
    const results = findByCapec(list, capec_id)
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ count: results.length, results }, null, 2)
        }
      ]
    }
  }
)

// Start server
async function main() {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  // Log to stderr only (stdout is reserved for MCP protocol)
  process.stderr.write('fetch-cwe-list-mcp server started (stdio)\n')
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`)
  process.exit(1)
})
