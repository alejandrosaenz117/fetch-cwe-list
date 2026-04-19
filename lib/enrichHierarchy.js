'use strict'

/**
 * Parses Related_Weaknesses into a clean Hierarchy object:
 *   cwe.Hierarchy = {
 *     parents: ['693', '697'],     // CWE IDs where nature === 'ChildOf'
 *     relationships: [{ nature, cweId, viewId, ordinal }]
 *   }
 *
 * CWE_ID and View_ID arrive as numbers from fast-xml-parser; String() normalizes them.
 *
 * @param {object} cwe - A single CWE weakness object (mutated in place)
 */
function enrichHierarchy(cwe) {
  if (!cwe.Related_Weaknesses?.Related_Weakness) return

  const raw = cwe.Related_Weaknesses.Related_Weakness
  const items = Array.isArray(raw) ? raw : [raw]

  const relationships = items.map((item) => ({
    nature: item.Nature,
    cweId: String(item.CWE_ID),
    viewId: String(item.View_ID),
    ordinal: item.Ordinal
  }))

  const parents = relationships
    .filter((r) => r.nature === 'ChildOf')
    .map((r) => r.cweId)

  cwe.Hierarchy = { parents, relationships }
}

module.exports = { enrichHierarchy }
