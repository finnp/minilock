# minilock
[![NPM](https://nodei.co/npm/minilock.png)](https://nodei.co/npm/minilock/)

[![Build Status](https://travis-ci.org/finnp/minilock.svg?branch=master)](https://travis-ci.org/finnp/minilock)

WIP

This module is based on the core of the [minilock-cli](https://www.npmjs.com/package/minilock-cli) module.

## example

```js
var minilock = require('minilock')
  minilock.encryptStream(alice.email, alice.passphrase, bob.id, function (err, encrypt) {
    minilock.decryptStream(bob.email, bob.passphrase, function (err, decrypt) {
        var stream = fs.createReadStream('test.js')
          .pipe(encrypt)
          .pipe(decrypt)
          .pipe(fs.createWriteStream('test-copy.js'))
        })
      })
    })
  })
})
```

## api

### encryptStream(email, passphrase, toid, callback)

**callback(error, encryptingStream)**

### decryptStream(email, passphrase, callback)

**callback(error, decryptingStream)**
