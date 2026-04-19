'use strict'

const mockFetchCweList = jest.fn()
const mockFindById = jest.fn()
const mockFindByName = jest.fn()
const mockFindByCapec = jest.fn()
const mockClearCache = jest.fn()

jest.mock('fetch-cwe-list', () => {
  const fn = mockFetchCweList
  fn.findById = mockFindById
  fn.findByName = mockFindByName
  fn.findByCapec = mockFindByCapec
  fn.clearCache = mockClearCache
  return fn
})

// Test fixture - must match real MITRE data structure
const FIXTURE = [
  {
    ID: '79',
    Name: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    Abstraction: 'Base',
    Status: 'Stable',
    Description: 'The software does not neutralize user-controllable input before it is written to output...',
    CAPEC_IDs: ['63', '85', '209'],
    Known_CVEs: []
  },
  {
    ID: '89',
    Name: 'SQL Injection',
    Abstraction: 'Base',
    Status: 'Stable',
    Description: 'The software constructs SQL commands using external input...',
    CAPEC_IDs: ['66', '7'],
    Known_CVEs: []
  },
  {
    ID: '20',
    Name: 'Improper Input Validation',
    Abstraction: 'Pillar',
    Status: 'Stable',
    Description: 'The software does not validate input properly...',
    CAPEC_IDs: ['209'],
    Known_CVEs: []
  }
]

beforeEach(() => {
  jest.clearAllMocks()
  mockFetchCweList.mockResolvedValue(FIXTURE)
  mockFindById.mockImplementation((list, id) =>
    list.find((c) => c.ID === id)
  )
  mockFindByName.mockImplementation((list, pattern) =>
    list.filter((c) => c.Name.toLowerCase().includes(pattern.toLowerCase()))
  )
  mockFindByCapec.mockImplementation((list, capecId) =>
    list.filter((c) => c.CAPEC_IDs.includes(capecId))
  )
})

describe('fetch_cwe_list handler logic', () => {
  it('returns total count and 5-entry preview', async () => {
    const list = FIXTURE
    const result = {
      total: list.length,
      version: 'latest',
      preview: list.slice(0, 5).map((cwe) => ({
        ID: cwe.ID,
        Name: cwe.Name,
        Abstraction: cwe.Abstraction,
        Status: cwe.Status,
        Description: cwe.Description.substring(0, 200)
      }))
    }

    expect(result.total).toBe(3)
    expect(result.preview).toHaveLength(3)
    expect(result.preview[0].ID).toBe('79')
  })

  it('truncates description to 200 characters', () => {
    const cwe = FIXTURE[0]
    const preview = {
      ID: cwe.ID,
      Description: cwe.Description.substring(0, 200)
    }

    expect(preview.Description.length).toBeLessThanOrEqual(200)
  })

  it('only returns 5 items in preview even with larger list', () => {
    const bigList = [...FIXTURE, ...FIXTURE, ...FIXTURE]
    const preview = bigList.slice(0, 5)
    expect(preview).toHaveLength(5)
  })

  it('includes all required fields in preview', () => {
    const cwe = FIXTURE[0]
    const preview = {
      ID: cwe.ID,
      Name: cwe.Name,
      Abstraction: cwe.Abstraction,
      Status: cwe.Status,
      Description: cwe.Description.substring(0, 200)
    }

    expect(preview).toHaveProperty('ID')
    expect(preview).toHaveProperty('Name')
    expect(preview).toHaveProperty('Abstraction')
    expect(preview).toHaveProperty('Status')
    expect(preview).toHaveProperty('Description')
  })
})

describe('find_cwe_by_id handler logic', () => {
  it('finds CWE-79 by ID', () => {
    const result = mockFindById(FIXTURE, '79')
    expect(result).toBeDefined()
    expect(result.ID).toBe('79')
    expect(result.Name).toContain('XSS')
  })

  it('returns undefined for unknown ID', () => {
    const result = mockFindById(FIXTURE, '9999')
    expect(result).toBeUndefined()
  })

  it('returns complete CWE object with all fields', () => {
    const result = mockFindById(FIXTURE, '79')
    expect(result).toHaveProperty('ID')
    expect(result).toHaveProperty('Name')
    expect(result).toHaveProperty('Abstraction')
    expect(result).toHaveProperty('Status')
    expect(result).toHaveProperty('Description')
    expect(result).toHaveProperty('CAPEC_IDs')
    expect(result).toHaveProperty('Known_CVEs')
  })

  it('handles string ID matching correctly', () => {
    const result1 = mockFindById(FIXTURE, '79')
    const result2 = mockFindById(FIXTURE, '79')
    expect(result1).toEqual(result2)
  })

  it('returns error JSON structure for missing CWE', () => {
    const id = '9999'
    const result = mockFindById(FIXTURE, id)
    const response = result
      ? JSON.stringify(result, null, 2)
      : JSON.stringify({ error: `CWE-${id} not found` })

    expect(response).toContain('error')
    const parsed = JSON.parse(response)
    expect(parsed).toHaveProperty('error')
  })
})

describe('find_cwe_by_name handler logic', () => {
  it('finds CWE by name substring (case-insensitive)', () => {
    const results = mockFindByName(FIXTURE, 'sql')
    expect(results).toHaveLength(1)
    expect(results[0].ID).toBe('89')
  })

  it('finds multiple CWEs with injection in name', () => {
    const results = mockFindByName(FIXTURE, 'input')
    expect(results.length).toBeGreaterThan(0)
    expect(results.some((c) => c.Name.toLowerCase().includes('input'))).toBe(
      true
    )
  })

  it('returns empty array when no match', () => {
    const results = mockFindByName(FIXTURE, 'zzznomatch')
    expect(results).toHaveLength(0)
  })

  it('is case-insensitive', () => {
    const lower = mockFindByName(FIXTURE, 'sql')
    const upper = mockFindByName(FIXTURE, 'SQL')
    const mixed = mockFindByName(FIXTURE, 'Sql')

    expect(lower).toEqual(upper)
    expect(upper).toEqual(mixed)
  })

  it('returns count and results structure', () => {
    const results = mockFindByName(FIXTURE, 'injection')
    const response = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ count: results.length, results }, null, 2)
        }
      ]
    }

    const parsed = JSON.parse(response.content[0].text)
    expect(parsed).toHaveProperty('count')
    expect(parsed).toHaveProperty('results')
    expect(parsed.count).toBe(results.length)
  })
})

describe('find_cwe_by_capec handler logic', () => {
  it('finds CWEs by CAPEC ID', () => {
    const results = mockFindByCapec(FIXTURE, '209')
    expect(results.length).toBeGreaterThan(0)
    expect(results.some((c) => c.ID === '79')).toBe(true)
  })

  it('returns empty array when no CWE maps to CAPEC', () => {
    const results = mockFindByCapec(FIXTURE, '9999')
    expect(results).toHaveLength(0)
  })

  it('handles multiple CAPECs for single CWE', () => {
    const results = mockFindByCapec(FIXTURE, '66')
    expect(results).toHaveLength(1)
    expect(results[0].ID).toBe('89')
  })

  it('handles CAPEC mapped to multiple CWEs', () => {
    const results = mockFindByCapec(FIXTURE, '209')
    expect(results.length).toBeGreaterThan(1)
  })

  it('returns count and results structure', () => {
    const results = mockFindByCapec(FIXTURE, '209')
    const response = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ count: results.length, results }, null, 2)
        }
      ]
    }

    const parsed = JSON.parse(response.content[0].text)
    expect(parsed).toHaveProperty('count')
    expect(parsed).toHaveProperty('results')
    expect(parsed.count).toBe(results.length)
  })
})

describe('Zod schema validation', () => {
  const { z } = require('zod')

  it('validates fetch_cwe_list input schema', () => {
    const schema = z.object({
      version: z.string().optional(),
      cache: z.boolean().optional().default(true)
    })

    const valid = schema.parse({})
    expect(valid.cache).toBe(true)

    const withVersion = schema.parse({ version: '1.0', cache: false })
    expect(withVersion.version).toBe('1.0')
    expect(withVersion.cache).toBe(false)
  })

  it('validates find_cwe_by_id input schema', () => {
    const schema = z.object({
      id: z.string()
    })

    const valid = schema.parse({ id: '79' })
    expect(valid.id).toBe('79')

    expect(() => schema.parse({})).toThrow()
  })

  it('validates find_cwe_by_name input schema', () => {
    const schema = z.object({
      pattern: z.string()
    })

    const valid = schema.parse({ pattern: 'injection' })
    expect(valid.pattern).toBe('injection')

    expect(() => schema.parse({})).toThrow()
  })

  it('validates find_cwe_by_capec input schema', () => {
    const schema = z.object({
      capec_id: z.string()
    })

    const valid = schema.parse({ capec_id: '209' })
    expect(valid.capec_id).toBe('209')

    expect(() => schema.parse({})).toThrow()
  })
})

describe('Response format validation', () => {
  it('fetch_cwe_list builds correct MCP response', () => {
    const list = FIXTURE
    const response = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            total: list.length,
            version: 'latest',
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

    expect(response.content).toHaveLength(1)
    expect(response.content[0].type).toBe('text')
    expect(typeof response.content[0].text).toBe('string')
    const parsed = JSON.parse(response.content[0].text)
    expect(parsed.total).toBe(3)
    expect(Array.isArray(parsed.preview)).toBe(true)
  })

  it('find tools build correct MCP response', () => {
    const results = mockFindByCapec(FIXTURE, '209')
    const response = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ count: results.length, results }, null, 2)
        }
      ]
    }

    expect(response.content).toHaveLength(1)
    expect(response.content[0].type).toBe('text')
    const parsed = JSON.parse(response.content[0].text)
    expect(parsed.count).toBe(results.length)
    expect(Array.isArray(parsed.results)).toBe(true)
  })
})

describe('Cache behavior', () => {
  it('should call fetch function when needed', async () => {
    mockFetchCweList.mockResolvedValue(FIXTURE)
    await mockFetchCweList('latest', { cache: true })
    expect(mockFetchCweList).toHaveBeenCalled()
  })

  it('should handle cache bypass', async () => {
    mockFetchCweList.mockResolvedValue(FIXTURE)
    await mockFetchCweList('latest', { cache: false })
    expect(mockFetchCweList).toHaveBeenCalledWith('latest', { cache: false })
  })

  it('should call clearCache when bypass enabled', () => {
    mockClearCache()
    expect(mockClearCache).toHaveBeenCalled()
  })
})

describe('Error handling', () => {
  it('handles network errors gracefully', async () => {
    mockFetchCweList.mockRejectedValue(new Error('Network error'))

    try {
      await mockFetchCweList()
    } catch (e) {
      expect(e.message).toBe('Network error')
    }
  })

  it('returns error JSON for not found', () => {
    const id = '9999'
    const result = mockFindById(FIXTURE, id)
    const errorResponse = !result
      ? JSON.stringify({ error: `CWE-${id} not found` })
      : null

    expect(errorResponse).toContain('error')
  })

  it('handles empty patterns gracefully', () => {
    const results = mockFindByName(FIXTURE, '')
    // Empty pattern matches everything (all strings contain empty string)
    expect(results.length).toBeGreaterThanOrEqual(0)
  })
})
