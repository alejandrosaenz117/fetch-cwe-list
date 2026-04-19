'use strict'

const { enrichCapec } = require('../enrichCapec')

// Fixtures use numeric CAPEC_ID to match fast-xml-parser output.
describe('enrichCapec', () => {
  test('extracts CAPEC IDs as string array from array of patterns', () => {
    const cwe = {
      Related_Attack_Patterns: {
        Related_Attack_Pattern: [
          { CAPEC_ID: 103 },
          { CAPEC_ID: 181 }
        ]
      }
    }

    enrichCapec(cwe)

    expect(cwe.CAPEC_IDs).toEqual(['103', '181'])
  })

  test('handles single Related_Attack_Pattern object (not array)', () => {
    const cwe = {
      Related_Attack_Patterns: {
        Related_Attack_Pattern: { CAPEC_ID: 62 }
      }
    }

    enrichCapec(cwe)

    expect(cwe.CAPEC_IDs).toEqual(['62'])
  })

  test('sets CAPEC_IDs to empty array when no Related_Attack_Patterns', () => {
    const cwe = {}
    enrichCapec(cwe)
    expect(cwe.CAPEC_IDs).toEqual([])
  })

  test('sets CAPEC_IDs to empty array when Related_Attack_Pattern list is empty', () => {
    const cwe = {
      Related_Attack_Patterns: {
        Related_Attack_Pattern: []
      }
    }
    enrichCapec(cwe)
    expect(cwe.CAPEC_IDs).toEqual([])
  })
})
