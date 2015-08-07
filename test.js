var minilock = require('./')
var fs = require('fs')
var test = require('tape')
var hasha = require('hasha')

var alice = {
  email: 'test@test.de', // salt
  passphrase: 'happy careful but neighbour round develop therefore', // key
  id: '6dZ3gQinFhGH1FS7UwxU8Q29xNceBS78ZGdD7FwfKHC9g' // publickey
}

var bob = {
  email: 'bob@cat.org',
  passphrase: 'wheel mention steam open sheep drop scissors',
  id: 'cvoPZ4NCbQ4QxrgV3x2HUcSu6nH4odY4DDeR8HwXTyzN2'
}

var TEST_FILE = 'test.js'

test('encrypt/decrypt alice to alice', function (t) {
  t.plan(2)

  var encrypt = minilock.encryptStream(alice.email, alice.passphrase, alice.id)
  var decrypt = minilock.decryptStream(alice.email, alice.passphrase)
  decrypt.on('sender', function (id) {
    t.equal(id, alice.id, 'correct sender id')
  })
  hasha.fromFile(TEST_FILE, function (err, originalHash) {
    if (err) t.fail(err)
    var stream = fs.createReadStream('test.js')
      .pipe(encrypt)
      .pipe(decrypt)
    hasha.fromStream(stream, function (err, hash) {
      if (err) t.fail(err)
      t.equal(originalHash, hash, 'correct file hash')
    })
  })
})

test('encrypt/decrypt alice to bob', function (t) {
  t.plan(2)
  var encrypt = minilock.encryptStream(alice.email, alice.passphrase, bob.id)
  var decrypt = minilock.decryptStream(bob.email, bob.passphrase)
  decrypt.on('sender', function (id) {
    t.equal(id, alice.id, 'correct sender id')
  })
  hasha.fromFile(TEST_FILE, function (err, originalHash) {
    if (err) t.fail(err)
    var stream = fs.createReadStream('test.js')
      .pipe(encrypt)
      .pipe(decrypt)
    hasha.fromStream(stream, function (err, hash) {
      if (err) t.fail(err)
      t.equal(originalHash, hash, 'correct file hash')
    })
  })
})

