const axios = require('axios').default
const unzipper = require('unzipper')
const fs = require('fs')
const parser = require('xml2json')
const path = require('path')
const zipFileName = path.join(__dirname, 'output', 'cwec_latest.xml.zip')
let externalReferenceAry = []
const options = {
  object: false,
  reversible: false,
  coerce: false,
  sanitize: true,
  trim: true,
  arrayNotation: false,
  alternateTextNode: false
}

// Download the CWE zip file and save it locally
async function downloadCweZip (url, destPath) {
  const response = await axios.get(url, { responseType: 'arraybuffer' })
  await fs.promises.writeFile(destPath, response.data)
}

// Extract all XML files from the zip and return their buffers
async function extractXmlBuffersFromZip (zipPath) {
  const xmlBuffers = []
  await new Promise((resolve, reject) => {
    fs.createReadStream(zipPath)
      .pipe(unzipper.Parse())
      .on('entry', function (entry) {
        const fileName = entry.path
        if (fileName.endsWith('.xml')) {
          const chunks = []
          entry.on('data', chunk => chunks.push(chunk))
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

// Parse XML buffer to JSON using xml2json
function parseXmlBufferToJson (xmlBuffer, options) {
  const xmlPreview = xmlBuffer.toString('utf8', 0, 200)
  console.log('XML file preview:', xmlPreview)
  if (!xmlPreview.trim().startsWith('<?xml')) {
    throw new Error('Extracted file does not appear to be valid XML.')
  }
  const cweJson = parser.toJson(xmlBuffer)
  return JSON.parse(cweJson, options)
}

// Clean up temporary files
function cleanupFile (filePath) {
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  } catch (cleanupErr) {
    console.warn('Warning: Could not delete temporary files:', cleanupErr)
  }
}

const fetchCwecLatest = () => {
  return new Promise((resolve, reject) => {
    (async () => {
      try {
        const url = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
        await downloadCweZip(url, zipFileName)
        const xmlBuffers = await extractXmlBuffersFromZip(zipFileName)
        if (xmlBuffers.length === 0) return reject(new Error('No XML files found in the zip.'))
        const data = Buffer.concat(xmlBuffers)
        let cweParsed
        try {
          cweParsed = parseXmlBufferToJson(data, options)
        } catch (err) {
          return reject(err)
        }
        const cweWeaknessAry = cweParsed.Weakness_Catalog.Weaknesses.Weakness.map((x) => x)
        externalReferenceAry = cweParsed.Weakness_Catalog.External_References.External_Reference
        cleanupFile(zipFileName)
        resolve(cweWeaknessAry)
      } catch (error) {
        console.error(error)
        reject(error)
      }
    })()
  })
}

const getExternalReferencesByCwe = (cwe) => {
  if (Array.isArray(cwe.References.Reference)) {
    cwe.References.Full_Details = []
    for (const externalReferenceId of cwe.References.Reference) {
      const fullReferenceDetails = externalReferenceAry.find(
        (reference) => externalReferenceId.External_Reference_ID === reference.Reference_ID
      )
      cwe.References.Full_Details.push(fullReferenceDetails)
    }
  }
}

// TODO add optional parameters for deleting items and where to store them
const fetchCweList = async () => {
  const cweWeaknessAry = await fetchCwecLatest()
  for (const cwe of cweWeaknessAry) {
    if (cwe.References) getExternalReferencesByCwe(cwe)
  }
  // Cleanup is handled in fetchCwecLatest
  return cweWeaknessAry
}

module.exports = fetchCweList

if (require.main === module) {
  fetchCweList().then((list) => {
    console.log(`Fetched ${list.length} CWE entries.`)
    // Optionally print a sample entry
    console.log(JSON.stringify(list[0], null, 2))
  }).catch((err) => {
    console.error(err)
    process.exit(1)
  })
}
