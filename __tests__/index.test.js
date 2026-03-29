'use strict'

const path = require('path')
const EventEmitter = require('events')
const https = require('https')
const fs = require('fs')
const unzipper = require('unzipper')

jest.mock('https')
jest.mock('unzipper')

const fetchCweList = require('../index')
const {
  downloadCweZip,
  handleFileError,
  extractXmlBuffersFromZip,
  parseXmlBufferToJson,
  cleanupFile,
  getCweZipUrlAndPath,
  getExternalReferencesByCwe,
  fetchCwec,
  _setExternalReferenceAry
} = fetchCweList

// Parser options that match index.js
const XML_OPTIONS = {
  ignoreAttributes: false,
  attributeNamePrefix: '',
  trimValues: true,
  parseAttributeValue: true
}

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid CWE XML string for use in tests. */
function buildCweXml ({ weaknesses = [], externalRefs = [] } = {}) {
  const weaknessXml = weaknesses
    .map(
      (w) =>
        `<Weakness ID="${w.ID}" Name="${w.Name}" Abstraction="Base" Structure="Simple" Status="Stable"></Weakness>`
    )
    .join('')
  const refXml = externalRefs
    .map(
      (r) =>
        `<External_Reference Reference_ID="${r.Reference_ID}"><Title>${r.Title}</Title><URL>https://example.com</URL></External_Reference>`
    )
    .join('')
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<Weakness_Catalog>\n' +
    `  <Weaknesses>${weaknessXml}</Weaknesses>\n` +
    `  <External_References>${refXml}</External_References>\n` +
    '</Weakness_Catalog>'
  )
}

/**
 * Sets up mocks for the HTTPS download step.
 *  - fs.createWriteStream → mockFile (EventEmitter with close spy)
 *  - fs.unlink            → no-op callback
 *  - https.get            → calls callback with a response of the given statusCode
 *
 * When statusCode is 2xx, the mock response's pipe() emits 'finish' on the
 * destination stream so downloadCweZip resolves.
 */
function setupHttpsMock ({ statusCode = 200, triggerFinish = true } = {}) {
  const mockFile = new EventEmitter()
  mockFile.close = jest.fn((cb) => cb && cb())
  jest.spyOn(fs, 'createWriteStream').mockReturnValue(mockFile)
  jest.spyOn(fs, 'unlink').mockImplementation((p, cb) => cb && cb())

  const mockRequest = new EventEmitter()
  https.get.mockImplementation((url, callback) => {
    const mockResponse = {
      statusCode,
      pipe: jest.fn((dest) => {
        if (triggerFinish) process.nextTick(() => dest.emit('finish'))
      })
    }
    callback(mockResponse)
    return mockRequest
  })

  return { mockFile, mockRequest }
}

/**
 * Sets up mocks for the zip-extraction step.
 *  - unzipper.Parse        → mockParseStream (EventEmitter)
 *  - fs.createReadStream   → returns an object whose pipe() yields mockParseStream
 *
 * Tests can emit 'entry', 'close', or 'error' on mockParseStream directly.
 */
function setupUnzipperMock () {
  const mockParseStream = new EventEmitter()
  unzipper.Parse.mockReturnValue(mockParseStream)
  const mockReadStream = { pipe: jest.fn().mockReturnValue(mockParseStream) }
  jest.spyOn(fs, 'createReadStream').mockReturnValue(mockReadStream)
  return { mockParseStream, mockReadStream }
}

/**
 * Sets up the complete download + extraction pipeline used by fetchCwec /
 * fetchCweList.  When xmlContent is provided and emitEntries is true, a
 * synthetic zip entry containing that XML is emitted after createReadStream
 * is called.
 */
function setupFullPipelineMock ({ xmlContent, emitEntries = true } = {}) {
  setupHttpsMock()
  jest.spyOn(fs, 'existsSync').mockReturnValue(false)

  const mockParseStream = new EventEmitter()
  unzipper.Parse.mockReturnValue(mockParseStream)

  jest.spyOn(fs, 'createReadStream').mockImplementation(() => {
    const mockReadStream = { pipe: jest.fn().mockReturnValue(mockParseStream) }
    if (emitEntries && xmlContent) {
      process.nextTick(() => {
        const entry = new EventEmitter()
        entry.path = 'cwec_latest.xml'
        mockParseStream.emit('entry', entry)
        entry.emit('data', Buffer.from(xmlContent, 'utf8'))
        entry.emit('end')
        mockParseStream.emit('close')
      })
    } else {
      process.nextTick(() => mockParseStream.emit('close'))
    }
    return mockReadStream
  })
}

// ---------------------------------------------------------------------------

afterEach(() => {
  jest.resetAllMocks()
  jest.restoreAllMocks()
  // Reset module-level external reference array after every test
  _setExternalReferenceAry([])
})

// ---------------------------------------------------------------------------
// getCweZipUrlAndPath
// ---------------------------------------------------------------------------
describe('getCweZipUrlAndPath', () => {
  it('returns the latest URL when no version is provided', () => {
    const { url, zipPath } = getCweZipUrlAndPath()
    expect(url).toBe('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
    expect(zipPath).toContain('cwec_latest.xml.zip')
    expect(zipPath).toContain('output')
  })

  it('returns the latest URL when version is "latest"', () => {
    const { url, zipPath } = getCweZipUrlAndPath('latest')
    expect(url).toBe('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
    expect(zipPath).toContain('cwec_latest.xml.zip')
  })

  it('returns a versioned URL for a valid version string', () => {
    const { url, zipPath } = getCweZipUrlAndPath('4.16')
    expect(url).toBe('https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip')
    expect(zipPath).toContain('cwec_v4.16.xml.zip')
    expect(zipPath).toContain('output')
  })

  it('returns correct path in the output directory', () => {
    const { zipPath } = getCweZipUrlAndPath('4.16')
    expect(path.dirname(zipPath)).toBe(path.join(path.dirname(require.resolve('../index')), 'output'))
  })

  it('throws for an alphabetic version string', () => {
    expect(() => getCweZipUrlAndPath('abc')).toThrow('Invalid version format')
  })

  it('throws for a version with letters mixed in', () => {
    expect(() => getCweZipUrlAndPath('4.x')).toThrow('Invalid version format')
  })

  it('throws for a version string starting with "v"', () => {
    expect(() => getCweZipUrlAndPath('v4.16')).toThrow('Invalid version format')
  })

  it('throws for a version containing a forward slash', () => {
    expect(() => getCweZipUrlAndPath('4.16/evil')).toThrow('Invalid version format')
  })

  it('throws for a version containing a backslash', () => {
    expect(() => getCweZipUrlAndPath('4.16\\evil')).toThrow('Invalid version format')
  })
})

// ---------------------------------------------------------------------------
// parseXmlBufferToJson
// ---------------------------------------------------------------------------
describe('parseXmlBufferToJson', () => {
  it('parses a valid XML buffer into a JavaScript object', () => {
    const xml = '<?xml version="1.0"?><root><item attr="1">value</item></root>'
    const result = parseXmlBufferToJson(Buffer.from(xml, 'utf8'), XML_OPTIONS)
    expect(result).toBeDefined()
    expect(result.root).toBeDefined()
  })

  it('throws when the buffer does not start with an XML declaration', () => {
    const buf = Buffer.from('<not-xml>data</not-xml>', 'utf8')
    expect(() => parseXmlBufferToJson(buf, XML_OPTIONS)).toThrow(
      'does not appear to be valid XML'
    )
  })

  it('throws when the buffer contains only whitespace', () => {
    const buf = Buffer.from('   \n\t  ', 'utf8')
    expect(() => parseXmlBufferToJson(buf, XML_OPTIONS)).toThrow(
      'does not appear to be valid XML'
    )
  })

  it('accepts XML with leading whitespace before the declaration', () => {
    // The xmlPreview is trimmed, so leading whitespace is OK
    const xml = '   <?xml version="1.0"?><root/>'
    const result = parseXmlBufferToJson(Buffer.from(xml, 'utf8'), XML_OPTIONS)
    expect(result).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// cleanupFile
// ---------------------------------------------------------------------------
describe('cleanupFile', () => {
  it('deletes the file when it exists', () => {
    jest.spyOn(fs, 'existsSync').mockReturnValue(true)
    jest.spyOn(fs, 'unlinkSync').mockImplementation(() => {})

    cleanupFile('/tmp/test.zip')

    expect(fs.existsSync).toHaveBeenCalledWith('/tmp/test.zip')
    expect(fs.unlinkSync).toHaveBeenCalledWith('/tmp/test.zip')
  })

  it('does not attempt to delete a file that does not exist', () => {
    jest.spyOn(fs, 'existsSync').mockReturnValue(false)
    jest.spyOn(fs, 'unlinkSync').mockImplementation(() => {})

    cleanupFile('/tmp/nonexistent.zip')

    expect(fs.existsSync).toHaveBeenCalledWith('/tmp/nonexistent.zip')
    expect(fs.unlinkSync).not.toHaveBeenCalled()
  })

  it('logs a warning when deletion throws', () => {
    jest.spyOn(fs, 'existsSync').mockReturnValue(true)
    jest.spyOn(fs, 'unlinkSync').mockImplementation(() => {
      throw new Error('Permission denied')
    })
    jest.spyOn(console, 'warn').mockImplementation(() => {})

    cleanupFile('/tmp/test.zip')

    expect(console.warn).toHaveBeenCalledWith(
      'Warning: Could not delete temporary files:',
      expect.any(Error)
    )
  })
})

// ---------------------------------------------------------------------------
// handleFileError
// ---------------------------------------------------------------------------
describe('handleFileError', () => {
  it('closes the file, unlinks the path, and calls reject with the error', () => {
    const mockFile = { close: jest.fn() }
    const mockReject = jest.fn()
    jest.spyOn(fs, 'unlink').mockImplementation((p, cb) => cb && cb())

    const error = new Error('Simulated network error')
    handleFileError(mockFile, '/tmp/test.zip', mockReject, error)

    expect(mockFile.close).toHaveBeenCalled()
    expect(fs.unlink).toHaveBeenCalledWith('/tmp/test.zip', expect.any(Function))
    expect(mockReject).toHaveBeenCalledWith(error)
  })
})

// ---------------------------------------------------------------------------
// getExternalReferencesByCwe
// ---------------------------------------------------------------------------
describe('getExternalReferencesByCwe', () => {
  it('does nothing when the CWE has no References property', () => {
    const cwe = { ID: 79, Name: 'XSS' }
    getExternalReferencesByCwe(cwe)
    expect(cwe.References).toBeUndefined()
  })

  it('does nothing when References.Reference is not an array', () => {
    const cwe = { References: { Reference: null } }
    getExternalReferencesByCwe(cwe)
    expect(cwe.References.Full_Details).toBeUndefined()
  })

  it('does nothing when References.Reference is a single object (not array)', () => {
    const cwe = { References: { Reference: { External_Reference_ID: 'REF-1' } } }
    getExternalReferencesByCwe(cwe)
    expect(cwe.References.Full_Details).toBeUndefined()
  })

  it('populates Full_Details with matching external reference details', () => {
    _setExternalReferenceAry([
      { Reference_ID: 'REF-1', Title: 'OWASP Top 10' },
      { Reference_ID: 'REF-2', Title: 'CWE Research' }
    ])

    const cwe = {
      References: {
        Reference: [
          { External_Reference_ID: 'REF-1' },
          { External_Reference_ID: 'REF-2' }
        ]
      }
    }

    getExternalReferencesByCwe(cwe)

    expect(cwe.References.Full_Details).toHaveLength(2)
    expect(cwe.References.Full_Details[0]).toEqual({ Reference_ID: 'REF-1', Title: 'OWASP Top 10' })
    expect(cwe.References.Full_Details[1]).toEqual({ Reference_ID: 'REF-2', Title: 'CWE Research' })
  })

  it('pushes undefined for a reference ID that does not exist in the external array', () => {
    _setExternalReferenceAry([])

    const cwe = {
      References: {
        Reference: [{ External_Reference_ID: 'REF-NONEXISTENT' }]
      }
    }

    getExternalReferencesByCwe(cwe)

    expect(cwe.References.Full_Details).toHaveLength(1)
    expect(cwe.References.Full_Details[0]).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// downloadCweZip
// ---------------------------------------------------------------------------
describe('downloadCweZip', () => {
  it('resolves when the download completes successfully', async () => {
    setupHttpsMock()
    await expect(
      downloadCweZip('https://example.com/file.zip', '/tmp/file.zip')
    ).resolves.toBeUndefined()
    expect(fs.createWriteStream).toHaveBeenCalledWith('/tmp/file.zip')
    expect(https.get).toHaveBeenCalledWith('https://example.com/file.zip', expect.any(Function))
  })

  it('rejects with a descriptive error on a 404 response', async () => {
    setupHttpsMock({ statusCode: 404, triggerFinish: false })
    await expect(
      downloadCweZip('https://example.com/notfound.zip', '/tmp/file.zip')
    ).rejects.toThrow('CWE version not found')
  })

  it('rejects with a descriptive error on a 500 response', async () => {
    setupHttpsMock({ statusCode: 500, triggerFinish: false })
    await expect(
      downloadCweZip('https://example.com/error.zip', '/tmp/file.zip')
    ).rejects.toThrow('Failed to download file')
  })

  it('rejects when the request emits an error event', async () => {
    const mockFile = new EventEmitter()
    mockFile.close = jest.fn()
    jest.spyOn(fs, 'createWriteStream').mockReturnValue(mockFile)
    jest.spyOn(fs, 'unlink').mockImplementation((p, cb) => cb && cb())

    const mockRequest = new EventEmitter()
    // Do NOT call callback – simulate a connection-level error before response
    https.get.mockImplementation(() => mockRequest)

    const promise = downloadCweZip('https://example.com/file.zip', '/tmp/file.zip')
    process.nextTick(() => mockRequest.emit('error', new Error('Network failure')))

    await expect(promise).rejects.toThrow('Network failure')
  })
})

// ---------------------------------------------------------------------------
// extractXmlBuffersFromZip
// ---------------------------------------------------------------------------
describe('extractXmlBuffersFromZip', () => {
  it('returns XML buffer(s) extracted from the zip', async () => {
    const xmlContent = Buffer.from('<?xml version="1.0"?><root/>', 'utf8')
    const { mockParseStream } = setupUnzipperMock()

    const promise = extractXmlBuffersFromZip('/tmp/test.zip')

    process.nextTick(() => {
      const entry = new EventEmitter()
      entry.path = 'cwe.xml'
      mockParseStream.emit('entry', entry)
      entry.emit('data', xmlContent)
      entry.emit('end')
      mockParseStream.emit('close')
    })

    const result = await promise
    expect(result).toHaveLength(1)
    expect(result[0].toString()).toBe(xmlContent.toString())
  })

  it('accumulates multiple data chunks into a single buffer', async () => {
    const chunk1 = Buffer.from('<?xml version="1.0"?>', 'utf8')
    const chunk2 = Buffer.from('<root/>', 'utf8')
    const { mockParseStream } = setupUnzipperMock()

    const promise = extractXmlBuffersFromZip('/tmp/test.zip')

    process.nextTick(() => {
      const entry = new EventEmitter()
      entry.path = 'cwec.xml'
      mockParseStream.emit('entry', entry)
      entry.emit('data', chunk1)
      entry.emit('data', chunk2)
      entry.emit('end')
      mockParseStream.emit('close')
    })

    const [buf] = await promise
    expect(buf.toString()).toBe(chunk1.toString() + chunk2.toString())
  })

  it('skips non-XML entries and calls autodrain()', async () => {
    const { mockParseStream } = setupUnzipperMock()

    const entry = new EventEmitter()
    entry.path = 'readme.txt'
    entry.autodrain = jest.fn()

    const promise = extractXmlBuffersFromZip('/tmp/test.zip')

    process.nextTick(() => {
      mockParseStream.emit('entry', entry)
      mockParseStream.emit('close')
    })

    const result = await promise
    expect(result).toHaveLength(0)
    expect(entry.autodrain).toHaveBeenCalled()
  })

  it('rejects when the parse stream emits an error', async () => {
    const { mockParseStream } = setupUnzipperMock()

    const promise = extractXmlBuffersFromZip('/tmp/test.zip')
    process.nextTick(() => mockParseStream.emit('error', new Error('Zip parse error')))

    await expect(promise).rejects.toThrow('Zip parse error')
  })

  it('rejects when an entry stream emits an error', async () => {
    const { mockParseStream } = setupUnzipperMock()

    const entry = new EventEmitter()
    entry.path = 'cwe.xml'

    const promise = extractXmlBuffersFromZip('/tmp/test.zip')

    process.nextTick(() => {
      mockParseStream.emit('entry', entry)
      entry.emit('error', new Error('Entry read error'))
    })

    await expect(promise).rejects.toThrow('Entry read error')
  })
})

// ---------------------------------------------------------------------------
// fetchCwec
// ---------------------------------------------------------------------------
describe('fetchCwec', () => {
  it('returns an array of weakness objects for a valid XML catalog', async () => {
    const xmlContent = buildCweXml({
      weaknesses: [
        { ID: 79, Name: 'XSS' },
        { ID: 89, Name: 'SQL Injection' }
      ],
      externalRefs: [{ Reference_ID: 'REF-1', Title: 'OWASP' }]
    })
    setupFullPipelineMock({ xmlContent })

    const result = await fetchCwec('latest')

    expect(Array.isArray(result)).toBe(true)
    expect(result).toHaveLength(2)
    expect(result[0].ID).toBe(79)
    expect(result[1].ID).toBe(89)
  })

  it('throws when the zip contains no XML files', async () => {
    setupFullPipelineMock({ emitEntries: false })
    await expect(fetchCwec('latest')).rejects.toThrow('No XML files found in the zip')
  })

  it('throws when the download fails and cleans up the zip file', async () => {
    setupHttpsMock({ statusCode: 404, triggerFinish: false })
    jest.spyOn(fs, 'existsSync').mockReturnValue(false)
    await expect(fetchCwec('latest')).rejects.toThrow('CWE version not found')
  })

  it('passes through invalid version errors', async () => {
    await expect(fetchCwec('invalid!')).rejects.toThrow('Invalid version format')
  })
})

// ---------------------------------------------------------------------------
// fetchCweList (main export / end-to-end)
// ---------------------------------------------------------------------------
describe('fetchCweList', () => {
  it('is a function', () => {
    expect(typeof fetchCweList).toBe('function')
  })

  it('returns an enriched array of CWE weaknesses', async () => {
    const xmlContent = buildCweXml({
      weaknesses: [
        { ID: 79, Name: 'XSS' },
        { ID: 89, Name: 'SQL Injection' }
      ],
      externalRefs: [{ Reference_ID: 'REF-1', Title: 'OWASP' }]
    })
    setupFullPipelineMock({ xmlContent })

    const result = await fetchCweList()

    expect(Array.isArray(result)).toBe(true)
    expect(result[0].ID).toBe(79)
  })

  it('enriches references when a weakness has References', async () => {
    // Two <Weakness> elements are required so fast-xml-parser produces an array.
    const xmlContent =
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<Weakness_Catalog>\n' +
      '  <Weaknesses>\n' +
      '    <Weakness ID="79" Name="XSS" Abstraction="Base" Structure="Simple" Status="Stable">\n' +
      '      <References>\n' +
      '        <Reference External_Reference_ID="REF-1" Section="s1"/>\n' +
      '        <Reference External_Reference_ID="REF-2" Section="s2"/>\n' +
      '      </References>\n' +
      '    </Weakness>\n' +
      '    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Structure="Simple" Status="Stable">\n' +
      '    </Weakness>\n' +
      '  </Weaknesses>\n' +
      '  <External_References>\n' +
      '    <External_Reference Reference_ID="REF-1"><Title>OWASP Top 10</Title><URL>https://owasp.org</URL></External_Reference>\n' +
      '    <External_Reference Reference_ID="REF-2"><Title>CWE Spec</Title><URL>https://cwe.mitre.org</URL></External_Reference>\n' +
      '  </External_References>\n' +
      '</Weakness_Catalog>'

    setupFullPipelineMock({ xmlContent })

    const result = await fetchCweList()

    expect(result[0].References.Full_Details).toBeDefined()
    expect(result[0].References.Full_Details[0].Reference_ID).toBe('REF-1')
    expect(result[0].References.Full_Details[1].Reference_ID).toBe('REF-2')
  })

  it('propagates errors from fetchCwec', async () => {
    setupHttpsMock({ statusCode: 500, triggerFinish: false })
    jest.spyOn(fs, 'existsSync').mockReturnValue(false)
    await expect(fetchCweList()).rejects.toThrow('Failed to download file')
  })

  it('uses a specific version when provided', async () => {
    const xmlContent = buildCweXml({
      weaknesses: [
        { ID: 89, Name: 'SQL Injection' },
        { ID: 79, Name: 'XSS' }
      ],
      externalRefs: []
    })
    setupFullPipelineMock({ xmlContent })

    const result = await fetchCweList('4.16')

    expect(https.get).toHaveBeenCalledWith(
      expect.stringContaining('cwec_v4.16'),
      expect.any(Function)
    )
    expect(result[0].ID).toBe(89)
  })
})
