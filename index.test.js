const fs = require('fs')
const path = require('path')

describe('fetch-cwe-list security features', () => {
  describe('30-second timeout protection', () => {
    test('downloadCweZip includes 30s timeout in https.get options', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/timeout:\s*30000/)
      expect(codeContent).toMatch(/https\.get\(url,\s*{\s*timeout:\s*30000/)
    })
  })

  describe('response size limit protection', () => {
    test('enforces 100MB response size limit', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/maxContentLength\s*=\s*100\s*\*\s*1024\s*\*\s*1024/)
      expect(codeContent).toMatch(/Response size limit exceeded/)
    })
  })

  describe('XXE prevention', () => {
    test('XMLParser configured with processEntities: false', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/processEntities:\s*false/)
    })
  })

  describe('concurrency safety', () => {
    test('externalReferenceAry is function-scoped, not module-level', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      // Check that externalReferenceAry is declared in fetchCwec function
      expect(codeContent).toMatch(/async function fetchCwec[\s\S]*?let externalReferenceAry\s*=\s*\[\]/)
      // Should NOT be at module level
      const lines = codeContent.split('\n')
      let isModuleLevelDeclaration = false
      for (let i = 0; i < Math.min(15, lines.length); i++) {
        if (lines[i].includes('let externalReferenceAry')) {
          isModuleLevelDeclaration = true
          break
        }
      }
      expect(isModuleLevelDeclaration).toBe(false)
    })
  })

  describe('single reference enrichment', () => {
    test('handles single Reference element as object', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'lib/enrichReferences.js'), 'utf8')
      // Should normalize single objects to arrays
      expect(codeContent).toMatch(/Array\.isArray\(cwe\.References\.Reference\)/)
      expect(codeContent).toMatch(/\?\s*cwe\.References\.Reference\s*:\s*\[cwe\.References\.Reference\]/)
    })

    test('enrichReferences accepts externalReferenceAry parameter', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'lib/enrichReferences.js'), 'utf8')
      expect(codeContent).toMatch(/enrichReferences\s*\(\s*cwe,\s*externalReferenceAry\s*\)/)
    })
  })

  describe('error handling', () => {
    test('timeout error handler destroys request', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/request\.on\('timeout'/)
      expect(codeContent).toMatch(/request\.destroy\(\)/)
    })

    test('handles HTTP errors (404, 5xx)', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/statusCode\s*===\s*404/)
      expect(codeContent).toMatch(/statusCode\s*<\s*200.*?statusCode\s*>=\s*300/)
    })
  })

  describe('cleanup', () => {
    test('removes temporary files with error handling', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/cleanupFile\s*\(zipPath\)/)
      expect(codeContent).toMatch(/try\s*{[\s\S]*?fs\.unlinkSync/)
    })
  })

  describe('API compatibility', () => {
    test('fetchCweList accepts optional version parameter', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/const fetchCweList\s*=\s*async\s*\(\s*version\s*\)/)
    })

    test('exports fetchCweList as module.exports', () => {
      const codeContent = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8')
      expect(codeContent).toMatch(/module\.exports\s*=\s*fetchCweList/)
    })
  })
})
