'use strict'

const { enrichHierarchy } = require('../enrichHierarchy')

// Fixtures use numeric CWE_ID/View_ID to match what fast-xml-parser returns
// with parseAttributeValue:true. Enricher normalizes to strings.
describe('enrichHierarchy', () => {
  test('adds Hierarchy.parents array for ChildOf relationships', () => {
    const cwe = {
      Related_Weaknesses: {
        Related_Weakness: [
          { Nature: 'ChildOf', CWE_ID: 693, View_ID: 1000, Ordinal: 'Primary' },
          { Nature: 'ChildOf', CWE_ID: 697, View_ID: 1003 }
        ]
      }
    }

    enrichHierarchy(cwe)

    expect(cwe.Hierarchy).toEqual({
      parents: ['693', '697'],
      relationships: [
        { nature: 'ChildOf', cweId: '693', viewId: '1000', ordinal: 'Primary' },
        { nature: 'ChildOf', cweId: '697', viewId: '1003', ordinal: undefined }
      ]
    })
  })

  test('handles a single Related_Weakness object (not array)', () => {
    const cwe = {
      Related_Weaknesses: {
        Related_Weakness: { Nature: 'ChildOf', CWE_ID: 116, View_ID: 1000, Ordinal: 'Primary' }
      }
    }

    enrichHierarchy(cwe)

    expect(cwe.Hierarchy.parents).toEqual(['116'])
    expect(cwe.Hierarchy.relationships).toHaveLength(1)
  })

  test('does nothing when Related_Weaknesses is absent', () => {
    const cwe = {}
    enrichHierarchy(cwe)
    expect(cwe.Hierarchy).toBeUndefined()
  })

  test('Hierarchy.parents contains only ChildOf CWE IDs', () => {
    const cwe = {
      Related_Weaknesses: {
        Related_Weakness: [
          { Nature: 'ChildOf', CWE_ID: 20, View_ID: 1000 },
          { Nature: 'CanPrecede', CWE_ID: 601, View_ID: 1000 }
        ]
      }
    }

    enrichHierarchy(cwe)

    expect(cwe.Hierarchy.parents).toEqual(['20'])
    expect(cwe.Hierarchy.relationships).toHaveLength(2)
  })
})
