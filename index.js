const axios = require('axios')
const unzipper = require('unzipper')
const fs = require('fs')
const { XMLParser } = require('fast-xml-parser')
const path = require('path')
const zipFileName = path.join(__dirname, 'output', 'cwec_latest.xml.zip')
const filePath = path.join(__dirname, 'output')
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  parseAttributeValue: false,
  trimValues: true,
  processEntities: false
})

const fetchCwecLatest = async () => {
  let externalReferenceAry = []
  const response = await axios.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip', {
    responseType: 'arraybuffer',
    timeout: 30000,
    maxContentLength: 100 * 1024 * 1024
  })
  await new Promise((resolve, reject) => {
    fs.writeFile(zipFileName, response.data, (writeErr) => {
      if (writeErr) {
        reject(writeErr)
        return
      }
      resolve()
    })
  })
  const directory = await unzipper.Open.file(zipFileName)
  const resolvedBase = path.resolve(filePath)
  for (const entry of directory.files) {
    if (entry.type === 'Directory') continue
    const entryFullPath = path.resolve(resolvedBase, entry.path)
    if (!entryFullPath.startsWith(resolvedBase + path.sep)) {
      throw new Error(`Path traversal detected in ZIP entry: ${entry.path}`)
    }
    if (!entry.path.includes('cwec_v')) continue
    await new Promise((extractResolve, extractReject) => {
      entry.stream()
        .pipe(fs.createWriteStream(entryFullPath))
        .on('error', extractReject)
        .on('finish', extractResolve)
    })
    const data = await new Promise((resolve, reject) => {
      fs.readFile(entryFullPath, (err, fileData) => {
        if (err) {
          reject(err)
          return
        }
        resolve(fileData)
      })
    })
    const cweParsed = xmlParser.parse(data)
    let cweWeaknessAry = cweParsed.Weakness_Catalog.Weaknesses.Weakness
    // Handle single element vs array
    if (!Array.isArray(cweWeaknessAry)) {
      cweWeaknessAry = cweWeaknessAry ? [cweWeaknessAry] : []
    }
    let weaknessExternalRefs = cweParsed.Weakness_Catalog.External_References.External_Reference
    // Handle single element vs array
    if (!Array.isArray(weaknessExternalRefs)) {
      weaknessExternalRefs = weaknessExternalRefs ? [weaknessExternalRefs] : []
    }
    externalReferenceAry = weaknessExternalRefs
    return { cweWeaknessAry, externalReferenceAry, extractedXmlPath: entryFullPath }
  }
}

const getExternalReferencesByCwe = (cwe, externalReferenceAry) => {
  if (!cwe.References) return
  // Normalize to array to handle both single object and array cases
  const references = Array.isArray(cwe.References.Reference)
    ? cwe.References.Reference
    : cwe.References.Reference ? [cwe.References.Reference] : []
  if (references.length === 0) return
  cwe.References.Full_Details = []
  for (const externalReferenceId of references) {
    const fullReferenceDetails = externalReferenceAry.find(
      (reference) => externalReferenceId.External_Reference_ID === reference.Reference_ID
    )
    cwe.References.Full_Details.push(fullReferenceDetails)
  }
}

// TODO add optional parameters for deleting items and where to store them
const fetchCweList = async () => {
  const { cweWeaknessAry, externalReferenceAry, extractedXmlPath } = await fetchCwecLatest()
  try {
    for (const cwe of cweWeaknessAry) {
      if (cwe.References) getExternalReferencesByCwe(cwe, externalReferenceAry)
    }
    return cweWeaknessAry
  } finally {
    try { fs.unlinkSync(zipFileName) } catch (_) {}
    try { fs.unlinkSync(extractedXmlPath) } catch (_) {}
  }
}

module.exports = fetchCweList
