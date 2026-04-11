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

## API Reference

### `fetchCweList([version])`

**Parameters:**
- `version` (string, optional) — CWE version to fetch (e.g., `'4.13'`). Defaults to `'latest'`.

**Returns:**
- Promise resolving to array of CWE objects

**Throws:**
- Error if download fails, timeout occurs, or version not found

## Data Structure

Each CWE entry contains MITRE's fields plus enriched reference data:

```javascript
{
  ID: "1004",
  Name: "Sensitive Cookie Without 'HttpOnly' Flag",
  Status: "Incomplete",
  Description: "...",
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
  // ... other CWE fields
}
```

**Note:** Single references are automatically normalized to arrays and enriched just like multiple references.

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
