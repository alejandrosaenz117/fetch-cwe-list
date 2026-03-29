const { test, describe } = require('node:test')
const assert = require('node:assert/strict')
const { XMLParser } = require('fast-xml-parser')

// --- Helpers mirroring index.js logic ---

const parserOptions = {
  ignoreAttributes: false,
  attributeNamePrefix: '',
  trimValues: true,
  parseAttributeValue: true
}

function parseXmlBufferToJson (xmlBuffer) {
  const xmlPreview = xmlBuffer.toString('utf8', 0, 200)
  if (!xmlPreview.trim().startsWith('<?xml')) {
    throw new Error('Extracted file does not appear to be valid XML.')
  }
  const parser = new XMLParser(parserOptions)
  return parser.parse(xmlBuffer.toString('utf8'))
}

function getCweZipUrlAndPath (version) {
  const path = require('path')
  const rootDir = require('path').join(__dirname, '..')
  if (!version || version === 'latest') {
    return {
      url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
      zipPath: path.join(rootDir, 'output', 'cwec_latest.xml.zip')
    }
  }
  if (!/^\d+(\.\d+)*$/.test(version)) {
    throw new Error('Invalid version format. Use, for example, "4.16" or "latest".')
  }
  if (version.includes('..') || version.includes('/') || version.includes('\\')) {
    throw new Error('Invalid version: path traversal is not allowed.')
  }
  return {
    url: `https://cwe.mitre.org/data/xml/cwec_v${version}.xml.zip`,
    zipPath: path.join(rootDir, 'output', `cwec_v${version}.xml.zip`)
  }
}

const sampleCweXml = `<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="4.16" Date="2024-11-19"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Weaknesses>
    <Weakness ID="1" Name="CISQ Quality Measures (2020)" Abstraction="Pillar" Structure="Simple" Status="Incomplete">
      <Description>CISQ has defined a set of measures to quantify four major categories of software quality.</Description>
      <References>
        <Reference External_Reference_ID="REF-1"/>
      </References>
    </Weakness>
    <Weakness ID="2" Name="7PK - Security Features" Abstraction="Pillar" Structure="Simple" Status="Incomplete">
      <Description>This category organizes the Most Important Software Errors related to security features.</Description>
    </Weakness>
  </Weaknesses>
  <External_References>
    <External_Reference Reference_ID="REF-1">
      <Author>Object Management Group (OMG)</Author>
      <Title>Automated Source Code Security Measure (ASCSM)</Title>
      <URL>http://www.omg.org/spec/ASCSM/1.0/</URL>
      <Publication_Year>2016</Publication_Year>
      <Publication_Month>01</Publication_Month>
    </External_Reference>
  </External_References>
</Weakness_Catalog>`

describe('parseXmlBufferToJson', () => {
  test('parses valid CWE XML into a JS object', () => {
    const buf = Buffer.from(sampleCweXml, 'utf8')
    const result = parseXmlBufferToJson(buf)
    assert.ok(result.Weakness_Catalog, 'should have Weakness_Catalog root')
    assert.ok(result.Weakness_Catalog.Weaknesses, 'should have Weaknesses')
    assert.ok(Array.isArray(result.Weakness_Catalog.Weaknesses.Weakness), 'Weakness should be an array')
    assert.equal(result.Weakness_Catalog.Weaknesses.Weakness.length, 2, 'should have 2 weaknesses')
  })

  test('preserves weakness ID attribute', () => {
    const buf = Buffer.from(sampleCweXml, 'utf8')
    const result = parseXmlBufferToJson(buf)
    const first = result.Weakness_Catalog.Weaknesses.Weakness[0]
    assert.equal(first.ID, 1, 'CWE ID should be 1 (parsed as number with parseAttributeValue)')
    assert.equal(first.Name, 'CISQ Quality Measures (2020)', 'Name should match')
  })

  test('preserves External_References', () => {
    const buf = Buffer.from(sampleCweXml, 'utf8')
    const result = parseXmlBufferToJson(buf)
    const refs = result.Weakness_Catalog.External_References.External_Reference
    assert.ok(Array.isArray(refs) || typeof refs === 'object', 'External_References should be present')
    const ref = Array.isArray(refs) ? refs[0] : refs
    assert.equal(ref.Reference_ID, 'REF-1', 'Reference_ID should match')
  })

  test('throws for non-XML input', () => {
    const buf = Buffer.from('not xml content', 'utf8')
    assert.throws(() => parseXmlBufferToJson(buf), /does not appear to be valid XML/)
  })

  test('parses weakness descriptions', () => {
    const buf = Buffer.from(sampleCweXml, 'utf8')
    const result = parseXmlBufferToJson(buf)
    const weaknesses = result.Weakness_Catalog.Weaknesses.Weakness
    assert.ok(weaknesses[0].Description, 'first weakness should have Description')
    assert.ok(weaknesses[1].Description, 'second weakness should have Description')
  })
})

describe('getCweZipUrlAndPath', () => {
  test('uses latest URL when no version is given', () => {
    const { url } = getCweZipUrlAndPath()
    assert.equal(url, 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
  })

  test('uses latest URL when version is "latest"', () => {
    const { url } = getCweZipUrlAndPath('latest')
    assert.equal(url, 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
  })

  test('constructs versioned URL correctly', () => {
    const { url } = getCweZipUrlAndPath('4.16')
    assert.equal(url, 'https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip')
  })

  test('throws for invalid version format', () => {
    assert.throws(() => getCweZipUrlAndPath('abc'), /Invalid version format/)
  })

  test('throws for path traversal attempt', () => {
    assert.throws(() => getCweZipUrlAndPath('4.16/../../../etc/passwd'), /Invalid version/)
  })

  test('throws for version with slash', () => {
    assert.throws(() => getCweZipUrlAndPath('4.16/etc'), /Invalid version/)
  })
})

describe('fast-xml-parser integration', () => {
  test('XMLParser is importable and functional', () => {
    assert.ok(XMLParser, 'XMLParser should be exported from fast-xml-parser')
    const parser = new XMLParser(parserOptions)
    assert.ok(parser, 'XMLParser instance should be created successfully')
  })

  test('XMLParser handles attributes correctly', () => {
    const xml = `<?xml version="1.0"?><root attr="value"><child>text</child></root>`
    const parser = new XMLParser(parserOptions)
    const result = parser.parse(xml)
    assert.equal(result.root.attr, 'value', 'should parse attribute')
    assert.equal(result.root.child, 'text', 'should parse child text')
  })

  test('XMLParser trims values', () => {
    const xml = `<?xml version="1.0"?><root>  trimmed  </root>`
    const parser = new XMLParser(parserOptions)
    const result = parser.parse(xml)
    assert.equal(result.root, 'trimmed', 'should trim values')
  })

  test('XMLParser parses numeric attributes as numbers', () => {
    const xml = `<?xml version="1.0"?><item id="42" name="test"/>`
    const parser = new XMLParser(parserOptions)
    const result = parser.parse(xml)
    assert.equal(result.item.id, 42, 'should parse numeric attribute as number')
    assert.equal(result.item.name, 'test', 'should parse string attribute as string')
  })
})
