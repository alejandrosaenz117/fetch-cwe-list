const parser = require('fast-xml-parser');
const axios = require('axios').default;
const unzipper = require('unzipper');
const fs = require('fs');
const { parse } = require('path');
var parser2 = require('xml2json');

var options = {
  object: false,
  reversible: false,
  coerce: false,
  sanitize: true,
  trim: true,
  arrayNotation: true,
  alternateTextNode: false
};

xmlParse = () => {
  fs.readFile('./output/path/cwec_v4.2.xml', function (err, data) {
    //optional (it'll return an object in case it's not valid)
    console.log(data);
    var json = parser2.toJson(data);
    let x = JSON.parse(json, options);
    console.log(x.Weakness_Catalog.Weaknesses);
    //var jsonObj = parser.parse(data);
  });
};

getUser = async () => {
  try {
    const response = await axios.get('https://cwe.mitre.org/data/xml/cwec_latest.xml.zip', {
      responseType: 'arraybuffer'
    });
    fs.writeFile('test.zip', response.data, async (err) => {
      if (err) {
        return console.log(err);
      }
      console.log('The file was saved!');
      let path = 'output/path';
      fs.createReadStream('test.zip').pipe(unzipper.Extract({ path }));
    });
  } catch (error) {
    console.error(error);
  }
};

//getUser();
xmlParse();
