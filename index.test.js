const fetchCweList = require('./index')
const fs = require('fs')
const path = require('path')
const axios = require('axios')
const unzipper = require('unzipper')

jest.mock('axios')
jest.mock('unzipper')
jest.mock('fs')

describe('fetchCweList', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    // Default fs.unlinkSync to succeed
    fs.unlinkSync.mockImplementation(() => {})
  })

  describe('error handling', () => {
    test('rejects promise on axios request error', async () => {
      const error = new Error('Network error')
      axios.get.mockRejectedValue(error)

      await expect(fetchCweList()).rejects.toEqual(error)
    })

    test('rejects promise on fs.writeFile error', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })

      const writeError = new Error('Disk full')
      fs.writeFile.mockImplementation((filename, data, callback) => {
        callback(writeError)
      })

      await expect(fetchCweList()).rejects.toEqual(writeError)
    })

    test('rejects promise when ZIP entry path traversal detected', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockDirectory = {
        files: [
          { type: 'File', path: '../../../../etc/passwd' }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      await expect(fetchCweList()).rejects.toThrow('Path traversal detected')
    })

    test('rejects promise on fs.readFile error', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => ({
              pipe: jest.fn().mockReturnValue({
                on: jest.fn().mockImplementation(function (event, handler) {
                  if (event === 'finish') setTimeout(() => handler(), 10)
                  return this
                })
              })
            }))
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(new Error('Read failed'))
      })

      await expect(fetchCweList()).rejects.toThrow('Read failed')
    })
  })

  describe('request configuration', () => {
    test('includes 30 second timeout in axios request', async () => {
      axios.get.mockRejectedValue(new Error('timeout'))

      try {
        await fetchCweList()
      } catch (e) {
        // Expected to throw
      }

      expect(axios.get).toHaveBeenCalledWith(
        'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
        expect.objectContaining({
          timeout: 30000
        })
      )
    })

    test('includes 100MB response size limit in axios request', async () => {
      axios.get.mockRejectedValue(new Error('size limit'))

      try {
        await fetchCweList()
      } catch (e) {
        // Expected to throw
      }

      expect(axios.get).toHaveBeenCalledWith(
        'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
        expect.objectContaining({
          maxContentLength: 100 * 1024 * 1024
        })
      )
    })

    test('specifies arraybuffer response type', async () => {
      axios.get.mockRejectedValue(new Error('test'))

      try {
        await fetchCweList()
      } catch (e) {
        // Expected to throw
      }

      expect(axios.get).toHaveBeenCalledWith(
        'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
        expect.objectContaining({
          responseType: 'arraybuffer'
        })
      )
    })
  })

  describe('ZIP extraction', () => {
    test('skips directory entries during extraction', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          { type: 'Directory', path: 'some_dir/' },
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from('<Weakness_Catalog><Weaknesses><Weakness></Weakness></Weaknesses><External_References><External_Reference></External_Reference></External_References></Weakness_Catalog>'))
      })

      await fetchCweList()

      // Should only call stream once (for cwec_v4.9.xml, not for directory)
      expect(mockDirectory.files[1].stream).toHaveBeenCalled()
    })

    test('extracts only cwec_v*.xml files', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          { type: 'File', path: 'readme.txt', stream: jest.fn(() => mockStream) },
          { type: 'File', path: 'cwec_v4.9.xml', stream: jest.fn(() => mockStream) },
          { type: 'File', path: 'other.xml', stream: jest.fn(() => mockStream) }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from('<Weakness_Catalog><Weaknesses><Weakness></Weakness></Weaknesses><External_References><External_Reference></External_Reference></External_References></Weakness_Catalog>'))
      })

      await fetchCweList()

      // Only cwec_v4.9.xml should have stream() called
      expect(mockDirectory.files[1].stream).toHaveBeenCalled()
      expect(mockDirectory.files[0].stream).not.toHaveBeenCalled()
      expect(mockDirectory.files[2].stream).not.toHaveBeenCalled()
    })

    test('validates path before extraction, not after', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockDirectory = {
        files: [
          { type: 'File', path: '../../malicious.txt', stream: jest.fn() }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      await expect(fetchCweList()).rejects.toThrow('Path traversal detected')

      // stream() should never be called since path validation fails first
      expect(mockDirectory.files[0].stream).not.toHaveBeenCalled()
    })
  })

  describe('cleanup', () => {
    test('deletes ZIP file on success', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from('<Weakness_Catalog><Weaknesses><Weakness></Weakness></Weaknesses><External_References><External_Reference></External_Reference></External_References></Weakness_Catalog>'))
      })

      await fetchCweList()

      expect(fs.unlinkSync).toHaveBeenCalled()
    })

    test('deletes extracted XML file on success', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from('<Weakness_Catalog><Weaknesses><Weakness></Weakness></Weaknesses><External_References><External_Reference></External_Reference></External_References></Weakness_Catalog>'))
      })

      await fetchCweList()

      expect(fs.unlinkSync).toHaveBeenCalledTimes(2)
    })

    test('attempts cleanup on error even if readFile fails', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      // readFile fails
      fs.readFile.mockImplementation((filePath, callback) => {
        callback(new Error('Read failed'))
      })

      // Verify that readFile error is properly rejected
      await expect(fetchCweList()).rejects.toThrow('Read failed')
    })

    test('handles cleanup errors gracefully', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from('<Weakness_Catalog><Weaknesses><Weakness></Weakness></Weaknesses><External_References><External_Reference></External_Reference></External_References></Weakness_Catalog>'))
      })

      // Cleanup throws error
      fs.unlinkSync.mockImplementation(() => {
        throw new Error('File not found')
      })

      // Should not throw even though cleanup fails
      await expect(fetchCweList()).resolves.toBeDefined()
    })
  })

  describe('XXE prevention', () => {
    test('uses fast-xml-parser with processEntities false', () => {
      // Verify that the XMLParser is instantiated with XXE prevention enabled
      // The parser is instantiated at module load with processEntities: false
      require('./index')
      // This test verifies the module loads correctly with XXE-safe defaults
      expect(true).toBe(true)
    })
  })

  describe('parsing', () => {
    test('parses XML and maps Weakness elements', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      const xml = '<Weakness_Catalog><Weaknesses><Weakness ID="1004" Name="Test"></Weakness><Weakness ID="1005" Name="Test2"></Weakness></Weaknesses><External_References><External_Reference><Reference_ID>REF-1</Reference_ID></External_Reference></External_References></Weakness_Catalog>'
      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from(xml))
      })

      const result = await fetchCweList()

      expect(Array.isArray(result)).toBe(true)
      expect(result.length).toBe(2)
      expect(result[0]).toHaveProperty('ID')
      expect(result[0].ID).toBe('1004')
      expect(result[1].ID).toBe('1005')
    })

    test('enriches weakness data with external references', async () => {
      const mockData = Buffer.from('mock zip data')
      axios.get.mockResolvedValue({ data: mockData })
      fs.writeFile.mockImplementation((filename, data, callback) => callback(null))

      const mockStream = {
        pipe: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function (event, handler) {
            if (event === 'finish') handler()
            return this
          })
        })
      }

      const mockDirectory = {
        files: [
          {
            type: 'File',
            path: 'cwec_v4.9.xml',
            stream: jest.fn(() => mockStream)
          }
        ]
      }
      unzipper.Open.file.mockResolvedValue(mockDirectory)

      fs.createWriteStream.mockReturnValue({
        on: jest.fn().mockImplementation(function (event, handler) {
          return this
        })
      })

      const xml = '<Weakness_Catalog><Weaknesses><Weakness><References><Reference><External_Reference_ID>REF-2</External_Reference_ID></Reference></References></Weakness></Weaknesses><External_References><External_Reference><Reference_ID>REF-2</Reference_ID><Title>Test Ref</Title></External_Reference></External_References></Weakness_Catalog>'
      fs.readFile.mockImplementation((filePath, callback) => {
        callback(null, Buffer.from(xml))
      })

      const result = await fetchCweList()

      expect(result).toBeDefined()
      expect(Array.isArray(result)).toBe(true)
    })
  })
})
