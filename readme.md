# minilock [![Dependency Status](https://david-dm.org/finnp/minilock.svg)](https://david-dm.org/finnp/minilock) [![Build Status](https://travis-ci.org/finnp/minilock.svg?branch=master)](https://travis-ci.org/finnp/minilock)
[![NPM](https://nodei.co/npm/minilock.png)](https://nodei.co/npm/minilock/)

WIP

This module is based on the core of the [minilock-cli](https://www.npmjs.com/package/minilock-cli) module.

It's a node implementation of the [miniLock](https://github.com/kaepora/miniLock) encryption.

## example

```js
var minilock = require('minilock')
minilock.encryptStream(alice.email, alice.passphrase, bob.id, function (err, encrypt) {
  minilock.decryptStream(bob.email, bob.passphrase, function (err, decrypt) {
      var stream = fs.createReadStream('test.js')
        .pipe(encrypt)
        .pipe(decrypt)
        .pipe(fs.createWriteStream('test-copy.js'))
      decrypt.on('sender', function (minilockID) {
        console.log('sender was', minilockID)
      })
  })
})
```

## api
Note: The streaming interfaces will load the entire input stream into memory.

### encryptStream(email, passphrase, toid[, opts])

Options
* `fileName` fileName for the encryption (will be empty by default)
* `chunkSize` chunkSize to use

### decryptStream(email, passphrase)

emits the sender's miniLockID with a 'sender' event

### publicKeyFromId(id)

returns a Uint8Array

### idFromPublicKey(publicKey)

publicKey as Uint8Array