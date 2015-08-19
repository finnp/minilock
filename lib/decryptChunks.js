var nacl = require('tweetnacl')
var naclStream = require('nacl-stream')
var debug = require('debug')
var stream = require('stream')
var BLAKE2s = require('blake2s-js')
var util = require('./util')

module.exports = decryptChunks

function decryptChunks () {
  var transform = new stream.Transform()
  var originalFilename = null
  var buffer = new Buffer(0)
  var hash = new BLAKE2s(32)
  var decryptInfo = null
  var decryptor = null

  transform._transform = function (chunk, enc, cb) {
    buffer = Buffer.concat([buffer, chunk])
    var push = function (chunk) {
      if (!originalFilename && chunk.length > 0) {
        // The very first chunk is the original filename.
        originalFilename = chunk.toString()
        // Strip out any trailing null characters.
        this.emit('fileName', (originalFilename + '\0').slice(0, originalFilename.indexOf('\0')))
      } else {
        this.push(chunk)
      }
    }.bind(this)
    // Decrypt as many chunks as possible.
    if (!decryptor) return cb(new Error('setDecryptInfo not called yet'))
    decryptChunk(buffer, decryptor, push, hash)
    cb()
  }
  transform._flush = function (cb) {
    if (nacl.util.encodeBase64(hash.digest()) !== decryptInfo.fileInfo.fileHash) {
      // The 32-byte BLAKE2 hash of the ciphertext must match the value in
      // the header.
      return cb(new Error('integrity check failed'))
    }
    cb()
  }
  transform.setDecryptInfo = function (_decryptInfo) {
    decryptInfo = _decryptInfo
    decryptor = naclStream.stream.createDecryptor(
        nacl.util.decodeBase64(decryptInfo.fileInfo.fileKey),
        nacl.util.decodeBase64(decryptInfo.fileInfo.fileNonce),
        0x100000)
  }
  return transform
}

function decryptChunk (chunk, decryptor, output, hash) {
  while (true) {
    var length = chunk.length >= 4 ? chunk.readUIntLE(0, 4, true) : 0
    if (chunk.length < 4 + 16 + length) break

    var encrypted = new Uint8Array(chunk.slice(0, 4 + 16 + length))
    var decrypted = decryptor.decryptChunk(encrypted, false)

    chunk = chunk.slice(4 + 16 + length)

    if (decrypted) {
      debug('Decrypted chunk ' + util.hex(decrypted))

      output(new Buffer(decrypted))
    }

    if (hash) hash.update(encrypted)
  }

  return chunk
}
