# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.0.12](https://github.com/alejandrosaenz117/fetch-cwe-list/compare/v0.0.10...v0.0.12) (2026-04-11)


### Bug Fixes

* **deps:** resolve all critical and high severity vulnerabilities ([2d6342e](https://github.com/alejandrosaenz117/fetch-cwe-list/commit/2d6342e3a1b954c9020981510c85888e09d86ad5))


### Others

* **release:** 0.0.11 ([b8037a8](https://github.com/alejandrosaenz117/fetch-cwe-list/commit/b8037a8d517a48977c4d34a4e50eb6b219d32e60))
* update repository URL to point to fork ([5e313ce](https://github.com/alejandrosaenz117/fetch-cwe-list/commit/5e313ce626dbdeae3b22cdf25cf42da3045ff1db))

### [0.0.11](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.10...v0.0.11) (2026-04-11)


### Bug Fixes

* **deps:** resolve all critical and high severity vulnerabilities ([2d6342e](https://github.com/Whamo12/fetch-cwe-list/commit/2d6342e3a1b954c9020981510c85888e09d86ad5))

### [0.0.10](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.9...v0.0.10) (2026-04-11)

### [0.0.9](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.3...v0.0.9) (2026-04-11)


### Features

* merge upstream v0.0.7 with enhanced security hardening ([b6762d5](https://github.com/Whamo12/fetch-cwe-list/commit/b6762d522fb81a765c51066f9e7ca2bef204cfef))


### Bug Fixes

* **deps:** upgrade axios ^1.15.0, unzipper ^0.12.3, replace xml2json with fast-xml-parser ([67fd580](https://github.com/Whamo12/fetch-cwe-list/commit/67fd580ece4ff69ccfeb0dea2323ae31691b3cb5))
* eliminate async promise executor and handle single references correctly ([f62c634](https://github.com/Whamo12/fetch-cwe-list/commit/f62c63497c67af6561cff31cf128305b29229e70))
* **index.js:** add 30s timeout and 100MB response size limit to axios request ([b1bd7bc](https://github.com/Whamo12/fetch-cwe-list/commit/b1bd7bc94b02e37e2fdfee45ce5d71fca653a887))
* **index.js:** handle single vs array elements in XML parsing ([9cefa22](https://github.com/Whamo12/fetch-cwe-list/commit/9cefa227ac33aa309ce003db5a9ba4b882041db1))
* **index.js:** move externalReferenceAry to function scope to prevent concurrent call data leakage ([8c623f0](https://github.com/Whamo12/fetch-cwe-list/commit/8c623f0008864674755eee68da6a8a944ceea9e5))
* **index.js:** propagate fs.writeFile errors to the promise instead of silently hanging ([31cc35b](https://github.com/Whamo12/fetch-cwe-list/commit/31cc35b6f928fd33eef73645156e421002740242))
* **index.js:** replace xml2json with fast-xml-parser to eliminate XXE attack surface ([934db90](https://github.com/Whamo12/fetch-cwe-list/commit/934db909b92390e59293d97b81f1d4bcc0f32f18))
* **index.js:** use unzipper.Open for pre-extraction Zip Slip validation ([3c76c66](https://github.com/Whamo12/fetch-cwe-list/commit/3c76c665240459092e634a4e7e7e5757b2ce966c))


### Others

* **deps:** bump json5 from 1.0.1 to 1.0.2 ([8f049b6](https://github.com/Whamo12/fetch-cwe-list/commit/8f049b6011436fae84afd2993cee97692b7d628a))
* npm audit fix to resolve transitive dependency vulnerabilities ([66cacc8](https://github.com/Whamo12/fetch-cwe-list/commit/66cacc8f7dcf7e64bfe3cadda54acb5d4decbbf5))
* **release:** 0.0.8 ([394dd95](https://github.com/Whamo12/fetch-cwe-list/commit/394dd95ac2899f1c487c71a94dd65210a30d7a26))
* update package-lock.json for Jest devDependency ([3c8c92d](https://github.com/Whamo12/fetch-cwe-list/commit/3c8c92d6d83eade9efe71d0ac6abc03ec6f8b84c))


### Tests

* add security feature verification tests for v0.0.8 ([9eaff83](https://github.com/Whamo12/fetch-cwe-list/commit/9eaff83569c527f7806dfba256ac16afa8aed45e))
* **index.test.js:** add comprehensive unit tests with 92% coverage ([8bb7d01](https://github.com/Whamo12/fetch-cwe-list/commit/8bb7d012361a5849d210838223fbb5fa91cc722c))


### Docs

* add comprehensive testing report documenting 92.3% code coverage ([1097168](https://github.com/Whamo12/fetch-cwe-list/commit/10971687f1b6c7affe9c80246af90b63d54e6265))
* redesign README for better UX and scannability ([c13c6e8](https://github.com/Whamo12/fetch-cwe-list/commit/c13c6e8cf8d400da8200f9e41aecf4566fb608f2))

### [0.0.8](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.3...v0.0.8) (2026-04-11)


### Features

* merge upstream v0.0.7 with enhanced security hardening ([b6762d5](https://github.com/Whamo12/fetch-cwe-list/commit/b6762d522fb81a765c51066f9e7ca2bef204cfef))


### Bug Fixes

* **deps:** upgrade axios ^1.15.0, unzipper ^0.12.3, replace xml2json with fast-xml-parser ([67fd580](https://github.com/Whamo12/fetch-cwe-list/commit/67fd580ece4ff69ccfeb0dea2323ae31691b3cb5))
* eliminate async promise executor and handle single references correctly ([f62c634](https://github.com/Whamo12/fetch-cwe-list/commit/f62c63497c67af6561cff31cf128305b29229e70))
* **index.js:** add 30s timeout and 100MB response size limit to axios request ([b1bd7bc](https://github.com/Whamo12/fetch-cwe-list/commit/b1bd7bc94b02e37e2fdfee45ce5d71fca653a887))
* **index.js:** handle single vs array elements in XML parsing ([9cefa22](https://github.com/Whamo12/fetch-cwe-list/commit/9cefa227ac33aa309ce003db5a9ba4b882041db1))
* **index.js:** move externalReferenceAry to function scope to prevent concurrent call data leakage ([8c623f0](https://github.com/Whamo12/fetch-cwe-list/commit/8c623f0008864674755eee68da6a8a944ceea9e5))
* **index.js:** propagate fs.writeFile errors to the promise instead of silently hanging ([31cc35b](https://github.com/Whamo12/fetch-cwe-list/commit/31cc35b6f928fd33eef73645156e421002740242))
* **index.js:** replace xml2json with fast-xml-parser to eliminate XXE attack surface ([934db90](https://github.com/Whamo12/fetch-cwe-list/commit/934db909b92390e59293d97b81f1d4bcc0f32f18))
* **index.js:** use unzipper.Open for pre-extraction Zip Slip validation ([3c76c66](https://github.com/Whamo12/fetch-cwe-list/commit/3c76c665240459092e634a4e7e7e5757b2ce966c))


### Tests

* **index.test.js:** add comprehensive unit tests with 92% coverage ([8bb7d01](https://github.com/Whamo12/fetch-cwe-list/commit/8bb7d012361a5849d210838223fbb5fa91cc722c))


### Docs

* add comprehensive testing report documenting 92.3% code coverage ([1097168](https://github.com/Whamo12/fetch-cwe-list/commit/10971687f1b6c7affe9c80246af90b63d54e6265))


### Others

* **deps:** bump json5 from 1.0.1 to 1.0.2 ([8f049b6](https://github.com/Whamo12/fetch-cwe-list/commit/8f049b6011436fae84afd2993cee97692b7d628a))
* npm audit fix to resolve transitive dependency vulnerabilities ([66cacc8](https://github.com/Whamo12/fetch-cwe-list/commit/66cacc8f7dcf7e64bfe3cadda54acb5d4decbbf5))
* update package-lock.json for Jest devDependency ([3c8c92d](https://github.com/Whamo12/fetch-cwe-list/commit/3c8c92d6d83eade9efe71d0ac6abc03ec6f8b84c))

### [0.0.3](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.2...v0.0.3) (2022-12-06)


### Bug Fixes

* **index.js:** there was an issue with parsing the XML file due to the version number changes ([5be3592](https://github.com/Whamo12/fetch-cwe-list/commit/5be359256ead1173ed4497c5c7a8692cc203cf96))

### [0.0.2](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.2-alpha.2...v0.0.2) (2020-11-29)

### [0.0.2-alpha.2](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.2-alpha.1...v0.0.2-alpha.2) (2020-11-29)

### [0.0.2-alpha.1](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.2-alpha.0...v0.0.2-alpha.1) (2020-11-29)


### Docs

* **package.json readme.md:** update README to include example. Add git cz ([88222d2](https://github.com/Whamo12/fetch-cwe-list/commit/88222d2cc5b16b8a1907968c56ca5ac7e8d9e427))

### [0.0.2-alpha.0](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.2-0...v0.0.2-alpha.0) (2020-11-29)

### [0.0.2-0](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.1...v0.0.2-0) (2020-11-29)

### [0.0.1](https://github.com/Whamo12/fetch-cwe-list/compare/v0.0.1-alpha.2...v0.0.1) (2020-11-29)

### [0.0.1-alpha.2](https://github.com/Whamo12/cwe-list/compare/v0.0.1-alpha.1...v0.0.1-alpha.2) (2020-11-29)

### [0.0.1-alpha.1](https://github.com/Whamo12/cwe-list/compare/v0.0.1-alpha.0...v0.0.1-alpha.1) (2020-11-29)

### 0.0.1-alpha.0 (2020-11-29)
