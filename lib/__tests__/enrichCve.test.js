'use strict'

const { enrichCve } = require('../enrichCve')

describe('enrichCve', () => {
  test('extracts CVE IDs and descriptions, skipping non-CVE references', () => {
    const cwe = {
      Observed_Examples: {
        Observed_Example: [
          { Reference: 'CVE-2008-0555', Description: 'CSS filtering bypass.' },
          { Reference: 'BID-12345', Description: 'Non-CVE reference.' },
          { Reference: 'CVE-2020-1234', Description: 'Another vulnerability.' }
        ]
      }
    }

    enrichCve(cwe)

    expect(cwe.Known_CVEs).toEqual([
      { id: 'CVE-2008-0555', description: 'CSS filtering bypass.' },
      { id: 'CVE-2020-1234', description: 'Another vulnerability.' }
    ])
  })

  test('handles single Observed_Example object (not array)', () => {
    const cwe = {
      Observed_Examples: {
        Observed_Example: { Reference: 'CVE-2021-9999', Description: 'Single example.' }
      }
    }

    enrichCve(cwe)

    expect(cwe.Known_CVEs).toEqual([
      { id: 'CVE-2021-9999', description: 'Single example.' }
    ])
  })

  test('sets Known_CVEs to empty array when no Observed_Examples', () => {
    const cwe = {}
    enrichCve(cwe)
    expect(cwe.Known_CVEs).toEqual([])
  })

  test('sets Known_CVEs to empty array when no CVE references exist', () => {
    const cwe = {
      Observed_Examples: {
        Observed_Example: [{ Reference: 'BID-12345', Description: 'Bugtraq only.' }]
      }
    }
    enrichCve(cwe)
    expect(cwe.Known_CVEs).toEqual([])
  })
})
