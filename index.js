var encrypt = require('./lib/encrypt')
var decrypt = require('./lib/decrypt')
var util = require('./lib/util')

module.exports.encryptStream = encrypt.encryptStream
module.exports.decryptStream = decrypt.decryptStream

module.exports.publicKeyFromId = util.publicKeyFromId
module.exports.idFromPublicKey = util.idFromPublicKey
