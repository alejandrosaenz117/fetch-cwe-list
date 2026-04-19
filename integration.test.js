'use strict'

/**
 * Integration tests — these make real HTTP requests to MITRE.
 * Run with: npm run test:integration
 *
 * Each test uses a 60-second timeout to account for network latency.
 */

const fetchCweList = require('./index')
const { findById, findByName, findByCapec, clearCache } = require('./index')

// Shared list fetched once for all tests
let cweList

beforeAll(async () => {
  clearCache()
  cweList = await fetchCweList()
}, 60000)

afterAll(() => {
  clearCache()
})

// ─── Shape & Size ────────────────────────────────────────────────────────────

describe('response shape', () => {
  test('returns an array', () => {
    expect(Array.isArray(cweList)).toBe(true)
  })

  test('returns more than 900 CWE entries', () => {
    expect(cweList.length).toBeGreaterThan(900)
  })

  test('every entry has a string ID', () => {
    const nonStringIds = cweList.filter(cwe => typeof cwe.ID !== 'string')
    expect(nonStringIds).toHaveLength(0)
  })

  test('every entry has a Name', () => {
    const missing = cweList.filter(cwe => !cwe.Name)
    expect(missing).toHaveLength(0)
  })

  test('every entry has a Description', () => {
    const missing = cweList.filter(cwe => !cwe.Description)
    expect(missing).toHaveLength(0)
  })
})

// ─── ID Normalization ─────────────────────────────────────────────────────────

describe('ID normalization', () => {
  test('IDs are strings, not numbers', () => {
    cweList.forEach(cwe => {
      expect(typeof cwe.ID).toBe('string')
    })
  })

  test('IDs are not empty strings', () => {
    cweList.forEach(cwe => {
      expect(cwe.ID.length).toBeGreaterThan(0)
    })
  })

  test('IDs contain only digits', () => {
    cweList.forEach(cwe => {
      expect(cwe.ID).toMatch(/^\d+$/)
    })
  })
})

// ─── CAPEC Enrichment ─────────────────────────────────────────────────────────

describe('CAPEC enrichment', () => {
  test('every entry has a CAPEC_IDs array', () => {
    const missing = cweList.filter(cwe => !Array.isArray(cwe.CAPEC_IDs))
    expect(missing).toHaveLength(0)
  })

  test('CAPEC_IDs contains strings not numbers', () => {
    cweList.forEach(cwe => {
      cwe.CAPEC_IDs.forEach(id => {
        expect(typeof id).toBe('string')
      })
    })
  })

  test('CWE-79 maps to CAPEC-63', () => {
    const cwe79 = findById(cweList, '79')
    expect(cwe79.CAPEC_IDs).toContain('63')
  })

  test('CWE-79 maps to CAPEC-209', () => {
    const cwe79 = findById(cweList, '79')
    expect(cwe79.CAPEC_IDs).toContain('209')
  })

  test('at least 300 CWEs have CAPEC mappings', () => {
    const withCapec = cweList.filter(cwe => cwe.CAPEC_IDs.length > 0)
    expect(withCapec.length).toBeGreaterThan(300)
  })
})

// ─── Hierarchy Enrichment ─────────────────────────────────────────────────────

describe('hierarchy enrichment', () => {
  test('CWE-79 has Hierarchy with parent CWE-74', () => {
    const cwe79 = findById(cweList, '79')
    expect(cwe79.Hierarchy).toBeDefined()
    expect(cwe79.Hierarchy.parents).toContain('74')
  })

  test('Hierarchy.relationships contains nature, cweId, viewId fields', () => {
    const cwe79 = findById(cweList, '79')
    const rel = cwe79.Hierarchy.relationships[0]
    expect(rel).toHaveProperty('nature')
    expect(rel).toHaveProperty('cweId')
    expect(rel).toHaveProperty('viewId')
  })

  test('Hierarchy.parents contains only ChildOf CWE IDs', () => {
    const cwe79 = findById(cweList, '79')
    const childOfIds = cwe79.Hierarchy.relationships
      .filter(r => r.nature === 'ChildOf')
      .map(r => r.cweId)
    expect(cwe79.Hierarchy.parents).toEqual(childOfIds)
  })

  test('Hierarchy relationship IDs are strings', () => {
    const cwe79 = findById(cweList, '79')
    cwe79.Hierarchy.relationships.forEach(rel => {
      expect(typeof rel.cweId).toBe('string')
      expect(typeof rel.viewId).toBe('string')
    })
  })
})

// ─── CVE Enrichment ───────────────────────────────────────────────────────────

describe('CVE enrichment', () => {
  test('every entry has a Known_CVEs array', () => {
    const missing = cweList.filter(cwe => !Array.isArray(cwe.Known_CVEs))
    expect(missing).toHaveLength(0)
  })

  test('Known_CVEs entries have id and description fields', () => {
    const withCves = cweList.filter(cwe => cwe.Known_CVEs.length > 0)
    withCves.forEach(cwe => {
      cwe.Known_CVEs.forEach(cve => {
        expect(cve).toHaveProperty('id')
        expect(cve).toHaveProperty('description')
      })
    })
  })

  test('all CVE IDs start with "CVE-"', () => {
    cweList.forEach(cwe => {
      cwe.Known_CVEs.forEach(cve => {
        expect(cve.id).toMatch(/^CVE-/)
      })
    })
  })

  test('CWE-79 has known CVEs', () => {
    const cwe79 = findById(cweList, '79')
    expect(cwe79.Known_CVEs.length).toBeGreaterThan(0)
  })

  test('CWE-79 Known_CVEs includes CVE-2021-1879', () => {
    const cwe79 = findById(cweList, '79')
    const ids = cwe79.Known_CVEs.map(c => c.id)
    expect(ids).toContain('CVE-2021-1879')
  })
})

// ─── References Enrichment ────────────────────────────────────────────────────

describe('references enrichment', () => {
  test('CWEs with references have Full_Details array', () => {
    const withRefs = cweList.filter(cwe => cwe.References?.Reference)
    withRefs.forEach(cwe => {
      expect(Array.isArray(cwe.References.Full_Details)).toBe(true)
    })
  })
})

// ─── Query Helpers ────────────────────────────────────────────────────────────

describe('query helpers', () => {
  test('findById returns CWE-79', () => {
    const result = findById(cweList, '79')
    expect(result).toBeDefined()
    expect(result.ID).toBe('79')
  })

  test('findById returns undefined for non-existent ID', () => {
    expect(findById(cweList, '99999')).toBeUndefined()
  })

  test('findByName returns results for "injection"', () => {
    const results = findByName(cweList, 'injection')
    expect(results.length).toBeGreaterThan(0)
  })

  test('findByName is case-insensitive', () => {
    const lower = findByName(cweList, 'injection')
    const upper = findByName(cweList, 'INJECTION')
    expect(lower.length).toBe(upper.length)
  })

  test('findByName throws TypeError for non-string pattern', () => {
    expect(() => findByName(cweList, /injection/)).toThrow(TypeError)
  })

  test('findByCapec returns CWEs for CAPEC-209', () => {
    const results = findByCapec(cweList, '209')
    expect(results.length).toBeGreaterThan(0)
  })

  test('findByCapec results all contain the queried CAPEC ID', () => {
    const results = findByCapec(cweList, '209')
    results.forEach(cwe => {
      expect(cwe.CAPEC_IDs).toContain('209')
    })
  })

  test('findByCapec includes CWE-79 when searching CAPEC-209', () => {
    const results = findByCapec(cweList, '209')
    const ids = results.map(c => c.ID)
    expect(ids).toContain('79')
  })
})

// ─── Cache ────────────────────────────────────────────────────────────────────

describe('cache', () => {
  test('second call returns same data without re-downloading', async () => {
    const start = Date.now()
    const list2 = await fetchCweList()
    const elapsed = Date.now() - start
    expect(list2.length).toBe(cweList.length)
    expect(elapsed).toBeLessThan(500) // should be instant
  }, 10000)

  test('cache returns a clone — mutating result does not corrupt cache', async () => {
    const list1 = await fetchCweList()
    const original = list1[0].Name
    list1[0].Name = 'POISONED'

    const list2 = await fetchCweList()
    expect(list2[0].Name).toBe(original)
  }, 10000)

  test('cache: false bypasses cache and returns fresh data', async () => {
    clearCache()
    const fresh = await fetchCweList('latest', { cache: false })
    expect(Array.isArray(fresh)).toBe(true)
    expect(fresh.length).toBeGreaterThan(900)
  }, 60000)

  test('clearCache() causes next call to re-fetch', async () => {
    clearCache()
    const list = await fetchCweList()
    expect(list.length).toBeGreaterThan(900)
  }, 60000)
})

// ─── Error Handling ───────────────────────────────────────────────────────────

describe('error handling', () => {
  test('throws error for invalid version format', async () => {
    await expect(fetchCweList('not-a-version')).rejects.toThrow('Invalid version format')
  }, 10000)

  test('throws error for non-existent version', async () => {
    await expect(fetchCweList('99.99')).rejects.toThrow()
  }, 60000)
})
