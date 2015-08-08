// based on: https://github.com/kaepora/miniLock/blob/b417c5164611cab8a79ece538ad6b47452797144/test/tests/deriveKey.js
// Key derivation test.
var minilock = require('../')
var test = require('tape')
var Base58 = require('bs58')
var nacl = require('tweetnacl')

var passphrase = 'This passphrase is supposed to be good enough for miniLock. :-)'

test('deriveKey', function (t) {
  minilock.getKeyPair(passphrase, 'miniLockScrypt..', function (keys) {
    t.deepEqual(Object.keys(keys).length, 2, 'sessionKeys is filled')
    t.deepEqual(typeof (keys), 'object', 'Type check')
    t.deepEqual(typeof (keys.publicKey), 'object', 'Public key type check')
    t.deepEqual(typeof (keys.secretKey), 'object', 'Secret key type check')
    t.deepEqual(keys.publicKey.length, 32, 'Public key length')
    t.deepEqual(keys.secretKey.length, 32, 'Secret key length')
    t.deepEqual(
    Base58.encode(keys.publicKey),
    'EWVHJniXUFNBC9RmXe45c8bqgiAEDoL3Qojy2hKt4c4e',
    'Public key Base58 representation'
    )
    t.deepEqual(
      nacl.util.encodeBase64(keys.secretKey),
      '6rcsdGAhF2rIltBRL+gwvQTQT7JMyei/d2JDrWoo0yw=',
      'Secret key Base64 representation'
    )
    t.deepEqual(
      minilock.getMiniLockID(keys.publicKey),
      '22d9pyWnHVGQTzCCKYEYbL4YmtGfjMVV3e5JeJUzLNum8A',
      'miniLock ID from public key'
    )
  })
  t.end()
})
