var Base58 = require('bs58')
var BLAKE2s = require('blake2s-js')

module.exports.publicKeyFromId = publicKeyFromId
module.exports.idFromPublicKey = idFromPublicKey
module.exports.hex = hex

function publicKeyFromId (id) {
  // The last byte is the checksum, slice it off
  return new Uint8Array(Base58.decode(id).slice(0, 32))
}

function idFromPublicKey (publicKey) {
  var hash = new BLAKE2s(1)
  hash.update(publicKey)

  // The last byte is the checksum.
  var checksum = new Buffer([hash.digest()[0]])

  var fullBuf = Buffer.concat([new Buffer(publicKey), checksum])
  return Base58.encode(fullBuf)
}

function hex (data) {
  return new Buffer(data).toString('hex')
}
