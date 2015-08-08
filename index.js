var encrypt = require('./lib/encrypt')
var decrypt = require('./lib/decrypt')
var util = require('./lib/util')
var getKeyPair = require('./lib/getkeypair.js')

module.exports.encryptStream = encrypt.encryptStream
module.exports.decryptStream = decrypt.decryptStream

module.exports.getKeyPair = getKeyPair

module.exports.publicKeyFromId = util.publicKeyFromId
module.exports.idFromPublicKey = util.idFromPublicKey
module.exports.getMiniLockID = util.idFromPublicKey

