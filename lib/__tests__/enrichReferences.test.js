'use strict'

const { enrichReferences } = require('../enrichReferences')

describe('enrichReferences', () => {
  test('normalizes numeric ID to string', () => {
    const cwe = { ID: 79 }
    const externalReferenceAry = []

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.ID).toBe('79')
    expect(typeof cwe.ID).toBe('string')
  })

  test('does nothing when ID is already a string', () => {
    const cwe = { ID: '89' }
    const externalReferenceAry = []

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.ID).toBe('89')
    expect(typeof cwe.ID).toBe('string')
  })

  test('returns early when References is absent', () => {
    const cwe = { ID: 79 }
    const externalReferenceAry = []

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.References).toBeUndefined()
  })

  test('attaches Full_Details for single reference', () => {
    const cwe = {
      ID: 79,
      References: {
        Reference: { External_Reference_ID: 'REF-6' }
      }
    }
    const externalReferenceAry = [
      { Reference_ID: 'REF-6', Title: 'Test Reference', URL: 'https://example.com' }
    ]

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.References.Full_Details).toHaveLength(1)
    expect(cwe.References.Full_Details[0]).toEqual({
      Reference_ID: 'REF-6',
      Title: 'Test Reference',
      URL: 'https://example.com'
    })
  })

  test('attaches Full_Details for array of references', () => {
    const cwe = {
      ID: 79,
      References: {
        Reference: [
          { External_Reference_ID: 'REF-6' },
          { External_Reference_ID: 'REF-7' }
        ]
      }
    }
    const externalReferenceAry = [
      { Reference_ID: 'REF-6', Title: 'Ref 6' },
      { Reference_ID: 'REF-7', Title: 'Ref 7' }
    ]

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.References.Full_Details).toHaveLength(2)
    expect(cwe.References.Full_Details[0].Reference_ID).toBe('REF-6')
    expect(cwe.References.Full_Details[1].Reference_ID).toBe('REF-7')
  })

  test('handles missing external reference details gracefully', () => {
    const cwe = {
      ID: 79,
      References: {
        Reference: { External_Reference_ID: 'REF-MISSING' }
      }
    }
    const externalReferenceAry = []

    enrichReferences(cwe, externalReferenceAry)

    expect(cwe.References.Full_Details).toHaveLength(1)
    expect(cwe.References.Full_Details[0]).toBeUndefined()
  })

  test('mutates the cwe object in place', () => {
    const cwe = { ID: 79, References: { Reference: { External_Reference_ID: 'REF-1' } } }
    const externalReferenceAry = [{ Reference_ID: 'REF-1', Title: 'Test' }]

    enrichReferences(cwe, externalReferenceAry)

    // Verify the original object was mutated
    expect(cwe.ID).toBe('79')
    expect(cwe.References.Full_Details).toBeDefined()
  })
})
