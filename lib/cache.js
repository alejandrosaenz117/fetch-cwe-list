'use strict'

const DEFAULT_TTL_SECONDS = 3600

/**
 * Creates an in-memory TTL cache with clone isolation.
 *
 * Security properties:
 *   - structuredClone on get() and set() — callers cannot corrupt cached state
 *   - Expired entries evicted on access — no stale reads
 *
 * @param {object} [opts]
 * @param {number} [opts.ttlSeconds=3600]
 * @returns {{ get(key: string): any|null, set(key: string, value: any): void, clear(): void }}
 */
function createCache({ ttlSeconds = DEFAULT_TTL_SECONDS } = {}) {
  const store = new Map()

  function get(key) {
    const entry = store.get(key)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      store.delete(key)
      return null
    }
    return structuredClone(entry.value)
  }

  function set(key, value) {
    store.set(key, {
      value: structuredClone(value),
      expiresAt: Date.now() + ttlSeconds * 1000
    })
  }

  function clear() {
    store.clear()
  }

  return { get, set, clear }
}

module.exports = { createCache }
