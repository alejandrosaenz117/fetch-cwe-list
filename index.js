const axios = require('axios').default
const unzipper = require('unzipper')
const fs = require('fs')
const parser = require('xml2json')
const path = require('path')
const zipFileName = path.join(__dirname, 'output', 'cwec_latest.xml.zip')
const xmlFileName = path.join(__dirname, 'output', 'cwec_v4.9.xml')
const filePath = path.join(__dirname, 'output')
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

const fetchCwecLatest = () => {
  // eslint-disable-next-line no-async-promise-executor
  return new Promise(async (resolve, reject) => {
    try {
      const response = await axios.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip', {
        responseType: 'arraybuffer'
      })
      fs.writeFile(zipFileName, response.data, async () => {
        const readStream = fs.createReadStream(zipFileName).pipe(unzipper.Extract({ path: filePath }))
        await new Promise((resolve) => readStream.on('close', resolve))
        fs.readdirSync(filePath).forEach((file) => {
          // The version changes but the intial file name is usually the same
          if (file.includes('cwec_v')) {
            const xmlFileName = file
            const xmlPath = path.join(__dirname, 'output', xmlFileName)
            fs.readFile(`${xmlPath}`, (err, data) => {
              if (err) {
                console.error(err)
              }
              const cweJson = parser.toJson(data)
              const cweParsed = JSON.parse(cweJson, options)
              const cweWeaknessAry = cweParsed.Weakness_Catalog.Weaknesses.Weakness.map((x) => x)
              externalReferenceAry = cweParsed.Weakness_Catalog.External_References.External_Reference
              resolve(cweWeaknessAry)
            })
          }
        })
      })
    } catch (error) {
      console.error(error)
      reject(error)
    }
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
  fs.unlinkSync(zipFileName)
  fs.unlinkSync(`${xmlFileName}`)
  return cweWeaknessAry
}

module.exports = fetchCweList
