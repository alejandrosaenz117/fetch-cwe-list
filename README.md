# fetch-cwe-list

[![npm](https://img.shields.io/npm/v/fetch-cwe-list)](https://www.npmjs.com/package/fetch-cwe-list)

A simple, secure Node.js module that fetches and parses the latest Common Weakness Enumeration (CWE) list from MITRE.

## Quick Start

```bash
npm install fetch-cwe-list
```

```javascript
const fetchCweList = require('fetch-cwe-list')

// Fetch latest CWE list
const cweList = await fetchCweList()
console.log(`Fetched ${cweList.length} CWE entries`)

// Fetch specific version
const cweListV413 = await fetchCweList('4.13')
```

That's it. Each entry includes parsed CWE data with enriched external references.

## Features

- **Live data** — Always current, fetched directly from MITRE
- **Enriched** — CAPEC mappings, CVE context, hierarchy relationships, external references
- **Cached** — Optional 1-hour TTL cache (configurable)
- **Query helpers** — `findById`, `findByName`, `findByCapec` for common lookups
- **Secure** — 30s timeout, 100MB size limit, XXE protection, no shared state
- **TypeScript** — Full type definitions included

## Usage

### Fetch and iterate

```javascript
const cweList = await fetchCweList()
cweList.forEach(cwe => {
  console.log(`${cwe.ID}: ${cwe.Name}`)
})
```

### Use query helpers

```javascript
const { findById, findByName, findByCapec } = require('fetch-cwe-list')
const cweList = await fetchCweList()

const cwe79      = findById(cweList, '79')
const injections = findByName(cweList, 'injection')
const xssCwes    = findByCapec(cweList, '209')  // CAPEC-209: XSS Using MIME Type Mismatch
```

### Access enriched data

```javascript
const cweList = await fetchCweList()
const cwe79 = findById(cweList, '79')

// CAPEC attack patterns
console.log(cwe79.CAPEC_IDs)  // ['63', '85', '209', '588', '591', '592']

// Hierarchy (parent weaknesses)
console.log(cwe79.Hierarchy.parents)  // ['74']

// Known CVEs
cwe79.Known_CVEs.forEach(({ id, description }) => {
  console.log(`${id}: ${description}`)
})
```

### Cache control

```javascript
const { clearCache } = require('fetch-cwe-list')

const list1 = await fetchCweList()  // Downloads, caches for 1 hour
const list2 = await fetchCweList()  // Instant (cached)

// Bypass cache
const fresh = await fetchCweList('latest', { cache: false })

// Invalidate cache
clearCache()
```

## API Reference

### `fetchCweList([version], [opts])`

**Parameters:**
- `version` (string, optional) — CWE version to fetch (e.g., `'4.13'`). Defaults to `'latest'`.
- `opts` (object, optional) — Options:
  - `cache` (boolean, optional) — Set to `false` to bypass cache. Default: `true`

**Returns:**
- Promise resolving to array of CWE objects

**Throws:**
- Error if download fails, timeout occurs, or version not found

### `clearCache()`

Clears the in-memory cache. The cache instance itself is not exposed to prevent external poisoning via `cache.set()`.

### `findById(cweList, id)`

Find a single CWE by its ID string.

**Parameters:**
- `cweList` — Array returned by `fetchCweList()`
- `id` (string) — The CWE ID, e.g., `'79'`

**Returns:**
- CWE object or `undefined`

### `findByName(cweList, pattern)`

Find all CWEs whose name contains the given string (case-insensitive).

**Parameters:**
- `cweList` — Array returned by `fetchCweList()`
- `pattern` (string) — Case-insensitive substring

**Returns:**
- Array of CWE objects

**Note:** RegExp is intentionally not supported to prevent ReDoS attacks.

### `findByCapec(cweList, capecId)`

Find all CWEs that map to a given CAPEC ID string.

**Parameters:**
- `cweList` — Array returned by `fetchCweList()`
- `capecId` (string) — The CAPEC ID, e.g., `'86'`

**Returns:**
- Array of CWE objects

## Data Structure

Each CWE entry contains MITRE's fields plus enriched data after v0.1.0:

| Field | Type | Always present | Description |
|-------|------|---------------|-------------|
| `ID` | `string` | Yes | CWE ID (normalized from numeric parser output) |
| `CAPEC_IDs` | `string[]` | Yes | Mapped CAPEC attack pattern IDs (empty array if none) |
| `Known_CVEs` | `{ id, description }[]` | Yes | CVEs from Observed_Examples (empty array if none) |
| `Hierarchy` | object | No | Parent relationships (absent if no Related_Weaknesses) |
| `References.Full_Details` | object[] | No | Enriched external reference objects |

Example entry:

```javascript
{
  ID: "79",
  Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  Status: "Stable",
  Description: "...",
  CAPEC_IDs: ['63', '85', '209', '588', '591', '592'],
  Known_CVEs: [
    { id: 'CVE-2021-1879', description: '...' }
  ],
  Hierarchy: {
    parents: ['74'],
    relationships: [
      { nature: 'ChildOf', cweId: '74', viewId: '1000', ordinal: 'Primary' }
    ]
  },
  References: {
    Reference: [{ External_Reference_ID: "REF-2" }],
    Full_Details: [
      {
        Reference_ID: "REF-2",
        Author: "OWASP",
        Title: "Cross Site Scripting (XSS)",
        URL: "https://www.owasp.org/..."
      }
    ]
  }
}
```

**Note:** Single references are automatically normalized to arrays and enriched just like multiple references. IDs are normalized to strings for consistency across all API surfaces.

## MCP Server

> **Experimental:** Alpha release. APIs may change.

An [MCP server](https://www.npmjs.com/package/fetch-cwe-list-mcp) is available for using this library as tools in LLM agents like Claude Code, Codex, etc.:

```bash
npx fetch-cwe-list-mcp
```

See [packages/fetch-cwe-list-mcp](packages/fetch-cwe-list-mcp/README.md) for full setup and usage.

## License

MIT

## Author

[Alejandro Saenz](https://github.com/alejandrosaenz117)
