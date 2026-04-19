'use strict'

/**
 * Extracts CVE IDs from Observed_Examples into a clean array:
 *   cwe.Known_CVEs = [{ id: 'CVE-2008-0555', description: '...' }]
 *
 * Only entries whose Reference starts with "CVE-" are included.
 * Always sets cwe.Known_CVEs — empty array if no CVE examples exist.
 *
 * @param {object} cwe - A single CWE weakness object (mutated in place)
 */
function enrichCve(cwe) {
  if (!cwe.Observed_Examples?.Observed_Example) {
    cwe.Known_CVEs = []
    return
  }

  const raw = cwe.Observed_Examples.Observed_Example
  const items = Array.isArray(raw) ? raw : [raw]

  cwe.Known_CVEs = items
    .filter((item) => typeof item.Reference === 'string' && item.Reference.startsWith('CVE-'))
    .map((item) => ({
      id: item.Reference,
      description: item.Description
    }))
}

module.exports = { enrichCve }
