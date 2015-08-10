var duplexify = require('duplexify')
var pumpify = require('pumpify')
var getKeyPair = require('./getkeypair')
var util = require('./util')
var parseHeaderStream = require('./parseHeader')
var decryptChunksStream = require('./decryptChunks')

module.exports.decryptStream = decryptStream

function decryptStream (email, passphrase) {
  var stream = duplexify()
  getKeyPair(passphrase, email, function (keyPair) {
    var ourId = util.idFromPublicKey(keyPair.publicKey)
    var parseHeader = parseHeaderStream(keyPair, ourId)
    var decryptChunks = decryptChunksStream()
    parseHeader.on('decryptInfo', function (decryptInfo) {
      decryptChunks.setDecryptInfo(decryptInfo)
    })
    var transform = pumpify([
      parseHeader,
      decryptChunks
    ])
    parseHeader.on('sender', function (sender) {
      stream.emit('sender', sender)
    })
    decryptChunks.on('fileName', function (fileName) {
      stream.emit('fileName', fileName)
    })
    stream.setWritable(transform)
    stream.setReadable(transform)
  })
  return stream
}

