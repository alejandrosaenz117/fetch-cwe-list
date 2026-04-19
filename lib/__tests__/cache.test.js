'use strict'

const { createCache } = require('../cache')

describe('createCache', () => {
  test('returns null for a key that has never been set', () => {
    const cache = createCache()
    expect(cache.get('latest')).toBeNull()
  })

  test('returns a deep clone — mutating the returned value does not corrupt cache', () => {
    const cache = createCache({ ttlSeconds: 60 })
    cache.set('latest', [{ ID: '1', Name: 'Test' }])

    const result1 = cache.get('latest')
    result1[0].Name = 'POISONED'

    const result2 = cache.get('latest')
    expect(result2[0].Name).toBe('Test')  // Original name, not 'POISONED'
    expect(result2).not.toBe(result1)      // Different object reference
  })

  test('returns null when TTL has expired', () => {
    jest.useFakeTimers()
    const cache = createCache({ ttlSeconds: 60 })
    cache.set('latest', [{ ID: '1' }])

    jest.advanceTimersByTime(61 * 1000)

    expect(cache.get('latest')).toBeNull()
    jest.useRealTimers()
  })

  test('second write to same key wins, no corruption', () => {
    const cache = createCache()
    cache.set('latest', [{ ID: 'A' }])
    cache.set('latest', [{ ID: 'B' }])
    expect(cache.get('latest')[0].ID).toBe('B')
  })

  test('stores different values under different keys', () => {
    const cache = createCache()
    cache.set('latest', [{ ID: 'A' }])
    cache.set('4.13', [{ ID: 'B' }])
    expect(cache.get('latest')[0].ID).toBe('A')
    expect(cache.get('4.13')[0].ID).toBe('B')
  })

  test('clear() empties the cache', () => {
    const cache = createCache()
    cache.set('latest', [{ ID: '1' }])
    cache.clear()
    expect(cache.get('latest')).toBeNull()
  })
})
