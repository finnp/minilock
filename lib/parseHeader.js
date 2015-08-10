var nacl = require('tweetnacl')
var stream = require('stream')
var util = require('./util')

module.exports = parseHeader

function parseHeader (keyPair, ourId) {
  var transform = new stream.Transform()
  var buffer = new Buffer(0)
  var headerLength = -1
  var header = null
  var decryptInfo = null
  transform._transform = function (chunk, enc, cb) {
    if (!header) {
      buffer = Buffer.concat([buffer, chunk])
      // parse header
      if (headerLength < 0 && buffer.length >= 12) {
        // header length + magic number
        var magicNumber = buffer.slice(0, 8).toString()
        if (magicNumber !== 'miniLock') return cb(new Error('incorrect magic number'))
        headerLength = buffer.readUIntLE(8, 4, true)

        if (headerLength > 0x3fffffff) return cb(new Error('header too long'))
        buffer = new Buffer(buffer.slice(12))
      }
      if (headerLength > -1) {
        // Look for the JSON opening brace.
        if (buffer.length > 0 && buffer[0] !== 0x7b) return cb(new Error('JSON opening bracket missing'))

        if (buffer.length >= headerLength) {
          // Read the header and parse the JSON object.
          header = JSON.parse(buffer.slice(0, headerLength).toString())
          if (header.version !== 1) return cb(new Error('unsupported version'))
          if (!validateKey(header.ephemeral)) return cb(new Error('could not validate key'))

          decryptInfo = extractDecryptInfo(header, keyPair.secretKey)
          if (!decryptInfo || decryptInfo.recipientID !== ourId) return cb(new Error('Not a recipient'))
          this.emit('sender', decryptInfo.senderID)
          this.emit('decryptInfo', decryptInfo)
          buffer = buffer.slice(headerLength)
          // emit what is left of the buffer, and then clear it
          this.emit(buffer)
          buffer = false
        }
      }
    } else {
      this.push(chunk)
    }
    cb()
  }
  return transform
}

function validateKey (key) {
  var keyRegex = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
  if (!key) return false
  if (!(key.length >= 40 && key.length <= 50)) return false
  if (!keyRegex.test(key)) return false

  return nacl.util.decodeBase64(key).length === 32
}

function extractDecryptInfo (header, secretKey) {
  var decryptInfo = null

  var ephemeral = nacl.util.decodeBase64(header.ephemeral)

  for (var i in header.decryptInfo) {
    var nonce = nacl.util.decodeBase64(i)

    decryptInfo = nacl.util.decodeBase64(header.decryptInfo[i])
    decryptInfo = nacl.box.open(decryptInfo, nonce, ephemeral, secretKey)

    if (decryptInfo) {
      decryptInfo = JSON.parse(nacl.util.encodeUTF8(decryptInfo))

      decryptInfo.fileInfo = nacl.util.decodeBase64(decryptInfo.fileInfo)
      decryptInfo.fileInfo = nacl.box.open(decryptInfo.fileInfo, nonce, util.publicKeyFromId(decryptInfo.senderID), secretKey)

      decryptInfo.fileInfo = JSON.parse(
          nacl.util.encodeUTF8(decryptInfo.fileInfo)
          )
      break
    }
  }

  return decryptInfo
}
