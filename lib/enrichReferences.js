'use strict'

/**
 * Normalizes the weakness ID to a string (fast-xml-parser returns it as a
 * number when parseAttributeValue:true is set), normalizes single-reference
 * objects to arrays, and attaches full external reference details to
 * cwe.References.Full_Details.
 *
 * ID normalization lives here because this is the first enrichment step that
 * runs for every CWE — the single place where numeric IDs become the
 * canonical string form the public API guarantees.
 *
 * @param {object} cwe - A single CWE weakness object (mutated in place)
 * @param {Array}  externalReferenceAry - The External_References array from the catalog
 */
function enrichReferences(cwe, externalReferenceAry) {
  // Normalize numeric ID → string. fast-xml-parser returns attribute values
  // as numbers when parseAttributeValue:true. All public API callers expect strings.
  if (cwe.ID !== undefined) cwe.ID = String(cwe.ID)

  if (!cwe.References?.Reference) return

  const references = Array.isArray(cwe.References.Reference)
    ? cwe.References.Reference
    : [cwe.References.Reference]

  cwe.References.Full_Details = references.map((ref) =>
    externalReferenceAry.find(
      (extRef) => ref.External_Reference_ID === extRef.Reference_ID
    )
  )
}

module.exports = { enrichReferences }
