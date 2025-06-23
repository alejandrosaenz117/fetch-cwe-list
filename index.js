const axios = require('axios').default
const unzipper = require('unzipper')
const fs = require('fs')
const { XMLParser } = require('fast-xml-parser')
const path = require('path')
let externalReferenceAry = []
const options = {
  ignoreAttributes: false,
  attributeNamePrefix: '',
  trimValues: true,
  parseAttributeValue: true
}

// Download the CWE zip file and save it locally
async function downloadCweZip (url, destPath) {
  try {
    const response = await axios.get(url, { responseType: 'arraybuffer' })
    await fs.promises.writeFile(destPath, response.data)
  } catch (err) {
    if (err.response && err.response.status === 404) {
      throw new Error(`CWE version not found at ${url} (status: 404)`)
    }
    throw err
  }
}

// Extract all XML files from the zip and return their buffers
async function extractXmlBuffersFromZip (zipPath) {
  const xmlBuffers = []
  await new Promise((resolve, reject) => {
    fs.createReadStream(zipPath)
      .pipe(unzipper.Parse())
      .on('entry', (entry) => {
        const fileName = entry.path
        if (fileName.endsWith('.xml')) {
          const chunks = []
          entry.on('data', (chunk) => chunks.push(chunk))
          entry.on('end', () => xmlBuffers.push(Buffer.concat(chunks)))
          entry.on('error', reject)
        } else {
          entry.autodrain()
        }
      })
      .on('close', resolve)
      .on('error', reject)
  })
  return xmlBuffers
}

// Parse XML buffer to JSON using fast-xml-parser
function parseXmlBufferToJson (xmlBuffer, options) {
  const xmlPreview = xmlBuffer.toString('utf8', 0, 200)
  if (!xmlPreview.trim().startsWith('<?xml')) {
    throw new Error('Extracted file does not appear to be valid XML.')
  }
  const parser = new XMLParser(options)
  return parser.parse(xmlBuffer.toString('utf8'))
}

// Clean up temporary files
function cleanupFile (filePath) {
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  } catch (cleanupErr) {
    console.warn('Warning: Could not delete temporary files:', cleanupErr)
  }
}

// Helper to construct the correct URL and zip path for a given version
function getCweZipUrlAndPath (version) {
  let url, zipPath
  if (!version || version === 'latest') {
    url = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
    zipPath = path.join(__dirname, 'output', 'cwec_latest.xml.zip')
  } else {
    // Validate version string (e.g., "4.16")
    // Only allow digits and dots, and must match the MITRE version format
    if (!/^\d+(\.\d+)*$/.test(version)) {
      throw new Error('Invalid version format. Use, for example, "4.16" or "latest".')
    }
    // Prevent path traversal by rejecting any version with '..' or '/'
    if (version.includes('..') || version.includes('/') || version.includes('\\')) {
      throw new Error('Invalid version: path traversal is not allowed.')
    }
    url = `https://cwe.mitre.org/data/xml/cwec_v${version}.xml.zip`
    zipPath = path.join(__dirname, 'output', `cwec_v${version}.xml.zip`)
  }
  return { url, zipPath }
}

// Fetch and parse CWE catalog for a given version (or latest)
async function fetchCwec (version) {
  const { url, zipPath } = getCweZipUrlAndPath(version)
  try {
    await downloadCweZip(url, zipPath)
    const xmlBuffers = await extractXmlBuffersFromZip(zipPath)
    if (xmlBuffers.length === 0) throw new Error('No XML files found in the zip.')
    const data = Buffer.concat(xmlBuffers)
    const cweParsed = parseXmlBufferToJson(data, options)
    const cweWeaknessAry = cweParsed.Weakness_Catalog.Weaknesses.Weakness.map((x) => x)
    externalReferenceAry = cweParsed.Weakness_Catalog.External_References.External_Reference
    cleanupFile(zipPath)
    return cweWeaknessAry
  } catch (error) {
    cleanupFile(zipPath)
    throw error
  }
}

const getExternalReferencesByCwe = (cwe) => {
  if (Array.isArray(cwe.References?.Reference)) {
    cwe.References.Full_Details = []
    for (const externalReferenceId of cwe.References.Reference) {
      const fullReferenceDetails = externalReferenceAry.find(
        (reference) => externalReferenceId.External_Reference_ID === reference.Reference_ID
      )
      cwe.References.Full_Details.push(fullReferenceDetails)
    }
  }
}

// Main API: fetchCweList([version])
const fetchCweList = async (version) => {
  const cweWeaknessAry = await fetchCwec(version)
  for (const cwe of cweWeaknessAry) {
    if (cwe.References) getExternalReferencesByCwe(cwe)
  }
  return cweWeaknessAry
}

module.exports = fetchCweList

// CLI usage
if (require.main === module) {
  // Accept version as optional CLI argument
  const version = process.argv[2] || 'latest'
  fetchCweList(version).then((list) => {
    console.log(`Fetched ${list.length} CWE entries.`)
    // Optionally print a sample entry
    console.log(JSON.stringify(list[0], null, 2))
  }).catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
