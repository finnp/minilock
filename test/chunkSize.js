var minilock = require('../')
var test = require('tape')
var hasha = require('hasha')
var fs = require('fs')
var path = require('path')

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

var TEST_FILE = path.join(__dirname, 'minilock.png')

test('encrypt alice to bob with too small chunkSize', function (t) {
  t.plan(2)
  var encrypt = minilock.encryptStream(alice.email, alice.passphrase, bob.id, {chunkSize: 255})
  encrypt.on('error', function (err) {
    if (err) t.ok(err, 'error')
    t.ok(err.message.indexOf('size') > -1, 'error message')
  })
  encrypt.on('data', function () {
    t.fail('data event')
  })
  encrypt.write('test')
  encrypt.end()
})

test('encrypt/decrypt alice to bob with sufficient chunkSize', function (t) {
  t.plan(3)
  var encrypt = minilock.encryptStream(alice.email, alice.passphrase, bob.id, {chunkSize: 256})
  var decrypt = minilock.decryptStream(bob.email, bob.passphrase)
  encrypt.on('error', function (e) {
    t.fail(e.message)
  })
  decrypt.on('sender', function (id) {
    t.equal(id, alice.id, 'correct sender id')
  })
  decrypt.on('fileName', function (fileName) {
    t.equal(fileName, '', 'empty filename')
  })
  hasha.fromFile(TEST_FILE, function (err, originalHash) {
    if (err) t.fail(err)
    var stream = fs.createReadStream(TEST_FILE)
      .pipe(encrypt)
      .pipe(decrypt)
    hasha.fromStream(stream, function (err, hash) {
      if (err) t.fail(err)
      t.equal(originalHash, hash, 'correct file hash')
    })
  })
})
