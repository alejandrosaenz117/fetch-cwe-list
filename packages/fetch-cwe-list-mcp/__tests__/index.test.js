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

const FIXTURE = [
  {
    ID: '79',
    Name: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    Abstraction: 'Base',
    Status: 'Stable',
    Description: 'The software does not neutralize user-controllable input...',
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

describe('fetch_cwe_list tool', () => {
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
    expect(result.total).toBe(2)
    expect(result.preview).toHaveLength(2)
    expect(result.preview[0].ID).toBe('79')
  })
})

describe('find_cwe_by_id tool', () => {
  it('finds CWE-79 by ID', () => {
    const result = mockFindById(FIXTURE, '79')
    expect(result).toBeDefined()
    expect(result.Name).toContain('XSS')
  })

  it('returns undefined for unknown ID', () => {
    const result = mockFindById(FIXTURE, '9999')
    expect(result).toBeUndefined()
  })
})

describe('find_cwe_by_name tool', () => {
  it('finds CWE by name substring (case-insensitive)', () => {
    const results = mockFindByName(FIXTURE, 'injection')
    expect(results).toHaveLength(1)
    expect(results[0].ID).toBe('89')
  })

  it('returns empty array when no match', () => {
    const results = mockFindByName(FIXTURE, 'zzznomatch')
    expect(results).toHaveLength(0)
  })
})

describe('find_cwe_by_capec tool', () => {
  it('finds CWEs by CAPEC ID', () => {
    const results = mockFindByCapec(FIXTURE, '209')
    expect(results).toHaveLength(1)
    expect(results[0].ID).toBe('79')
  })

  it('returns empty array when no CWE maps to CAPEC', () => {
    const results = mockFindByCapec(FIXTURE, '9999')
    expect(results).toHaveLength(0)
  })
})
