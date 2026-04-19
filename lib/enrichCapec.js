'use strict'

/**
 * Extracts CAPEC attack pattern IDs into a flat string array:
 *   cwe.CAPEC_IDs = ['103', '181']
 *
 * CAPEC_ID arrives as a number from fast-xml-parser; String() normalizes it.
 * Always sets cwe.CAPEC_IDs — empty array if no mappings exist.
 *
 * @param {object} cwe - A single CWE weakness object (mutated in place)
 */
function enrichCapec(cwe) {
  if (!cwe.Related_Attack_Patterns?.Related_Attack_Pattern) {
    cwe.CAPEC_IDs = []
    return
  }

  const raw = cwe.Related_Attack_Patterns.Related_Attack_Pattern
  const items = Array.isArray(raw) ? raw : [raw]

  cwe.CAPEC_IDs = items.map((item) => String(item.CAPEC_ID))
}

module.exports = { enrichCapec }
