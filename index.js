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

const fetchCwecLatest = () => {
  // eslint-disable-next-line no-async-promise-executor
  return new Promise(async (resolve, reject) => {
    let externalReferenceAry = []
    try {
      const response = await axios.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip', {
        responseType: 'arraybuffer',
        timeout: 30000,
        maxContentLength: 100 * 1024 * 1024
      })
      fs.writeFile(zipFileName, response.data, async (writeErr) => {
        if (writeErr) {
          reject(writeErr)
          return
        }
        const directory = await unzipper.Open.file(zipFileName)
        const resolvedBase = path.resolve(filePath)
        for (const entry of directory.files) {
          if (entry.type === 'Directory') continue
          const entryFullPath = path.resolve(resolvedBase, entry.path)
          if (!entryFullPath.startsWith(resolvedBase + path.sep)) {
            reject(new Error(`Path traversal detected in ZIP entry: ${entry.path}`))
            return
          }
          if (!entry.path.includes('cwec_v')) continue
          await new Promise((extractResolve, extractReject) => {
            entry.stream()
              .pipe(fs.createWriteStream(entryFullPath))
              .on('error', extractReject)
              .on('finish', extractResolve)
          })
          fs.readFile(entryFullPath, (err, data) => {
            if (err) {
              reject(err)
              return
            }
            const cweParsed = xmlParser.parse(data)
            const cweWeaknessAry = cweParsed.Weakness_Catalog.Weaknesses.Weakness.map((x) => x)
            externalReferenceAry = cweParsed.Weakness_Catalog.External_References.External_Reference
            resolve({ cweWeaknessAry, externalReferenceAry, extractedXmlPath: entryFullPath })
          })
          break
        }
      })
    } catch (error) {
      console.error(error)
      reject(error)
    }
  })
}

const getExternalReferencesByCwe = (cwe, externalReferenceAry) => {
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
