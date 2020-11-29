# fetch-cwe-list
A simple Node.js module that fetches and parses the latest Common Weakness Enumeration (CWE) list

## Install

```
npm install fetch-cwe-list
```

## Usage

```
const fetchCweList = require('fetch-cwe-list')

// Basic usage
fetchCweList().then((cweAry) => {
    console.log(cweAry)
})

// async/await
const cweAry = await fetchCweList();
```

## Author

[Alejandro Saenz](https://github.com/Whamo12)
