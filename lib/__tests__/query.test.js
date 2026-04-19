'use strict'

const { findById, findByName, findByCapec } = require('../query')

// IDs are strings here — enrichReferences normalizes them before data
// reaches query helpers.
const fixture = [
  { ID: '79', Name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', CAPEC_IDs: ['86', '198'] },
  { ID: '89', Name: 'SQL Injection', CAPEC_IDs: ['66', '7'] },
  { ID: '117', Name: 'Improper Output Neutralization for Logs', CAPEC_IDs: [] }
]

describe('findById', () => {
  test('returns matching CWE by ID string', () => {
    expect(findById(fixture, '79').Name).toMatch('Web Page Generation')
  })

  test('returns undefined when ID is not found', () => {
    expect(findById(fixture, '9999')).toBeUndefined()
  })
})

describe('findByName', () => {
  test('returns matching CWEs for a string pattern (case-insensitive)', () => {
    const results = findByName(fixture, 'neutralization')
    expect(results).toHaveLength(2)
    expect(results.map((c) => c.ID)).toEqual(expect.arrayContaining(['79', '117']))
  })

  test('returns empty array when no matches', () => {
    expect(findByName(fixture, 'nonexistent_weakness_xyz')).toEqual([])
  })

  test('throws TypeError when pattern is not a string', () => {
    expect(() => findByName(fixture, /^SQL/)).toThrow(TypeError)
    expect(() => findByName(fixture, 123)).toThrow(TypeError)
    expect(() => findByName(fixture, null)).toThrow(TypeError)
  })
})

describe('findByCapec', () => {
  test('returns CWEs that map to a given CAPEC ID', () => {
    const results = findByCapec(fixture, '66')
    expect(results).toHaveLength(1)
    expect(results[0].ID).toBe('89')
  })

  test('returns empty array when no CWE maps to the CAPEC ID', () => {
    expect(findByCapec(fixture, '9999')).toEqual([])
  })

  test('returns multiple CWEs when they share a CAPEC ID', () => {
    const multiFixture = [
      { ID: '1', Name: 'A', CAPEC_IDs: ['99'] },
      { ID: '2', Name: 'B', CAPEC_IDs: ['99', '100'] }
    ]
    const results = findByCapec(multiFixture, '99')
    expect(results).toHaveLength(2)
  })
})
