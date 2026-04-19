# fetch-cwe-list

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

## Why This Module?

**Secure by default:**
- ✅ **30-second timeout** — prevents slow-read DoS attacks
- ✅ **100MB response limit** — prevents memory exhaustion  
- ✅ **XXE protection** — XML entity expansion disabled
- ✅ **Concurrency safe** — no shared state between calls

**Developer friendly:**
- ✅ **Version pinning** — fetch any published CWE version
- ✅ **Reference enrichment** — external refs automatically mapped to full details
- ✅ **Single reference handling** — normalized consistently
- ✅ **Error handling** — clear, actionable error messages

## Usage Examples

### Fetch Latest CWE List

```javascript
const fetchCweList = require('fetch-cwe-list')

const cweList = await fetchCweList()
cweList.forEach(cwe => {
  console.log(`${cwe.ID}: ${cwe.Name}`)
})
```

### Fetch Specific Version

```javascript
// Fetch CWE v4.13
const cweList = await fetchCweList('4.13')
console.log(`Fetched ${cweList.length} entries for v4.13`)
```

### Handle Errors

```javascript
try {
  const cweList = await fetchCweList('4.99')  // Version not found
} catch (err) {
  console.error(err.message)
  // Output: "CWE version not found at ... (status: 404)"
}

try {
  const cweList = await fetchCweList()  // Timeout
} catch (err) {
  console.error(err.message)
  // Output: "Download timeout (30 seconds)"
}
```

### Use .then() Instead of Async/Await

```javascript
fetchCweList()
  .then(cweList => console.log(`Fetched ${cweList.length} CWE entries`))
  .catch(err => console.error('Failed:', err.message))
```

### Search CWE Entries

```javascript
const cweList = await fetchCweList()

// Find all injection weaknesses
const injections = cweList.filter(cwe => 
  cwe.Name.toLowerCase().includes('injection')
)
console.log(`Found ${injections.length} injection CWEs`)

// Find by ID
const cwe1004 = cweList.find(cwe => cwe.ID === '1004')
console.log(cwe1004.Name)  // "Sensitive Cookie Without 'HttpOnly' Flag"
```

### Access CAPEC Attack Pattern IDs

```javascript
const cweList = await fetchCweList()
const cwe79 = cweList.find(cwe => cwe.ID === '79')
console.log(cwe79.CAPEC_IDs)  // ['86', '198', ...]
```

### Find CWEs by CAPEC ID

```javascript
const { findByCapec } = require('fetch-cwe-list')
const cweList = await fetchCweList()
const xssCwes = findByCapec(cweList, '86')
```

### Traverse the CWE Hierarchy

```javascript
const cweList = await fetchCweList()
const cwe79 = cweList.find(cwe => cwe.ID === '79')
console.log(cwe79.Hierarchy.parents)        // ['74']
console.log(cwe79.Hierarchy.relationships)  // full relationship details
```

### Look Up Known CVEs

```javascript
const cweList = await fetchCweList()
const cwe89 = cweList.find(cwe => cwe.ID === '89')
cwe89.Known_CVEs.forEach(({ id, description }) => {
  console.log(`${id}: ${description}`)
})
```

### Use Query Helpers

```javascript
const { findById, findByName } = require('fetch-cwe-list')
const cweList = await fetchCweList()

const cwe79    = findById(cweList, '79')
const injections = findByName(cweList, 'injection')  // case-insensitive substring
```

### Cache Behavior

```javascript
const fetchCweList = require('fetch-cwe-list')
const { clearCache } = require('fetch-cwe-list')

// First call downloads from MITRE and caches for 1 hour
const cweList = await fetchCweList()

// Subsequent calls return cached data instantly
const cweList2 = await fetchCweList()

// Bypass the cache for a single call
const fresh = await fetchCweList('latest', { cache: false })

// Invalidate the cache manually (e.g. after a MITRE release)
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
  ID: "1004",
  Name: "Sensitive Cookie Without 'HttpOnly' Flag",
  Status: "Incomplete",
  Description: "...",
  CAPEC_IDs: ['62', '103'],
  Known_CVEs: [
    { id: 'CVE-2020-1234', description: 'Cookie bypass...' }
  ],
  Hierarchy: {
    parents: ['200', '693'],
    relationships: [
      { nature: 'ChildOf', cweId: '200', viewId: '1000', ordinal: 'Primary' }
    ]
  },
  References: {
    Reference: [
      { External_Reference_ID: "REF-2" }
    ],
    Full_Details: [
      {
        Reference_ID: "REF-2",
        Author: "OWASP",
        Title: "HttpOnly",
        URL: "https://www.owasp.org/..."
      }
    ]
  },
  // ... other MITRE CWE fields
}
```

**Note:** Single references are automatically normalized to arrays and enriched just like multiple references. IDs are normalized to strings for consistency across all API surfaces.

### Full Entry Example

Click to see a [complete CWE entry](./EXAMPLE_OUTPUT.md) with all fields.

## Security Details

This module protects against common attack vectors:

| Threat | Protection |
|--------|-----------|
| **Slow-read DoS** | 30-second timeout on downloads |
| **Memory exhaustion** | 100MB max response size |
| **XXE injection** | XML entity expansion disabled |
| **Data leakage** | Function-scoped state (no module-level shared state) |
| **Path traversal** | Version parameter validated |

## Troubleshooting

### "Download timeout (30 seconds)"

The MITRE server took too long to respond. This is rare but can happen if:
- Your network is slow
- MITRE servers are overloaded
- You're behind a restrictive firewall

**Solution:** Retry after a few seconds. Timeouts protect against slow-read DoS attacks.

### "CWE version not found"

The requested version doesn't exist in MITRE's archive. Valid versions include `'4.13'`, `'4.12'`, etc.

**Solution:** Use `'latest'` (or omit the parameter) to fetch the current version.

### "Response size limit exceeded"

The response was larger than 100MB. This is a security protection against memory exhaustion attacks.

**Solution:** This shouldn't happen with normal CWE data. If it does, report an issue.

## Version History

- **v0.0.8** — Security hardening: timeouts, response size limits, XXE prevention
- **v0.0.7** — Version pinning support
- **v0.0.6** — Switched to Node.js https module
- **v0.0.5** — Added specific version fetching
- **v0.0.4** — Migrated to fast-xml-parser
- **v0.0.3** — Initial release

## License

MIT

## Author

[Alejandro Saenz](https://github.com/Whamo12)
