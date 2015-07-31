var scrypt = require('scrypt-async')
var nacl = require('tweetnacl')
var BLAKE2s = require('blake2s-js')

module.exports = getKeyPair

function getKeyPair (key, salt, callback) {
  var keyHash = new BLAKE2s(32)
  keyHash.update(nacl.util.decodeUTF8(key))

  getScryptKey(keyHash.digest(), nacl.util.decodeUTF8(salt), function (keyBytes) {
    callback(nacl.box.keyPair.fromSecretKey(keyBytes))
  })
}

function getScryptKey (key, salt, callback) {
  scrypt(key, salt, 17, 8, 32, 1000, function scryptCb (keyBytes) {
    callback(nacl.util.decodeBase64(keyBytes))
  }, 'base64')
}
