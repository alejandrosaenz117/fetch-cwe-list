'use strict'

/**
 * Find a single CWE by its ID string.
 *
 * @param {Array}  cweList - Array returned by fetchCweList()
 * @param {string} id      - The CWE ID, e.g. '79'
 * @returns {object|undefined}
 */
function findById(cweList, id) {
  return cweList.find((cwe) => cwe.ID === id)
}

/**
 * Find all CWEs whose Name contains the given string (case-insensitive).
 *
 * RegExp is intentionally NOT supported: user-supplied catastrophic backtracking
 * patterns block the Node.js event loop across 959 CWE names for seconds.
 *
 * @param {Array}   cweList - Array returned by fetchCweList()
 * @param {string}  pattern - Case-insensitive substring
 * @returns {Array}
 * @throws {TypeError} if pattern is not a string
 */
function findByName(cweList, pattern) {
  if (typeof pattern !== 'string') {
    throw new TypeError(`findByName: pattern must be a string, got ${typeof pattern}`)
  }
  const lower = pattern.toLowerCase()
  return cweList.filter((cwe) => cwe.Name?.toLowerCase().includes(lower))
}

/**
 * Find all CWEs that map to a given CAPEC ID string.
 * Requires enrichCapec() to have run (cwe.CAPEC_IDs must be present).
 *
 * @param {Array}  cweList  - Array returned by fetchCweList()
 * @param {string} capecId  - The CAPEC ID, e.g. '86'
 * @returns {Array}
 */
function findByCapec(cweList, capecId) {
  return cweList.filter((cwe) => Array.isArray(cwe.CAPEC_IDs) && cwe.CAPEC_IDs.includes(capecId))
}

module.exports = { findById, findByName, findByCapec }
