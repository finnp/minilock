var nacl = require('tweetnacl')
var debug = require('debug')
var naclStream = require('nacl-stream')
var BLAKE2s = require('blake2s-js')
var stream = require('stream')
var duplexify = require('duplexify')
var getKeyPair = require('./getkeypair')
var util = require('./util')

module.exports.decryptStream = decryptStream
module.exports.decryptChunk = decryptChunk

function decryptStream (email, passphrase) {
  var stream = duplexify()
  getKeyPair(passphrase, email, function (keyPair) {
    var transform = decryptStreamWithKeyPair(keyPair)
    transform.on('sender', function (sender) {
      stream.emit('sender', sender)
    })
    transform.on('fileName', function (fileName) {
      stream.emit('fileName', fileName)
    })
    stream.setWritable(transform)
    stream.setReadable(transform)
  })
  return stream
}

function decryptStreamWithKeyPair (keyPair) {
  debug('Our public key is ' + util.hex(keyPair.publicKey))
  debug('Our secret key is ' + util.hex(keyPair.secretKey))

  var toId = util.idFromPublicKey(keyPair.publicKey)

  debug('Our miniLock ID is ' + toId)

  var headerLength = -1
  var header = null
  var decryptInfo = null
  var decryptor = null
  var hash = new BLAKE2s(32)
  var buffer = new Buffer(0)
  var originalFilename = null

  var transform = new stream.Transform()

  transform._transform = function (chunk, enc, cb) {
    buffer = Buffer.concat([buffer, chunk])

    if (!header) {
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
          this.emit('sender', decryptInfo.senderID)
          debug('Recipient: ' + decryptInfo.recipientID)
          if (!decryptInfo || decryptInfo.recipientID !== toId) return cb(new Error('Not a recipient'))
          buffer = buffer.slice(headerLength)
        }
      }
    }
    if (decryptInfo) {
      if (!decryptor) {
        decryptor = naclStream.stream.createDecryptor(
            nacl.util.decodeBase64(decryptInfo.fileInfo.fileKey),
            nacl.util.decodeBase64(decryptInfo.fileInfo.fileNonce),
            0x100000)
      }

      var push = function (chunk) {
        if (!originalFilename && chunk.length > 0) {
          // The very first chunk is the original filename.
          originalFilename = chunk
          // Strip out any trailing null characters.
          this.emit('fileName', (originalFilename + '\0').slice(0, originalFilename.indexOf('\0')))
        } else {
          this.push(chunk)
        }
      }.bind(this)
      // Decrypt as many chunks as possible.
      decryptChunk(buffer, decryptor, push, hash)
    }
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

function extractDecryptInfo (header, secretKey) {
  var decryptInfo = null

  var ephemeral = nacl.util.decodeBase64(header.ephemeral)

  for (var i in header.decryptInfo) {
    var nonce = nacl.util.decodeBase64(i)

    debug('Trying nonce ' + util.hex(nonce))

    decryptInfo = nacl.util.decodeBase64(header.decryptInfo[i])
    decryptInfo = nacl.box.open(decryptInfo, nonce, ephemeral, secretKey)

    if (decryptInfo) {
      decryptInfo = JSON.parse(nacl.util.encodeUTF8(decryptInfo))

      debug('Recipient ID is ' + decryptInfo.recipientID)
      debug('Sender ID is ' + decryptInfo.senderID)

      decryptInfo.fileInfo = nacl.util.decodeBase64(decryptInfo.fileInfo)
      decryptInfo.fileInfo = nacl.box.open(decryptInfo.fileInfo, nonce, util.publicKeyFromId(decryptInfo.senderID), secretKey)

      decryptInfo.fileInfo = JSON.parse(
          nacl.util.encodeUTF8(decryptInfo.fileInfo)
          )

      debug('File key is ' + util.hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileKey)))
      debug('File nonce is ' + util.hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileNonce)))
      debug('File hash is ' + util.hex(nacl.util.decodeBase64(
              decryptInfo.fileInfo.fileHash)))
      break
    }
  }

  return decryptInfo
}

function validateKey (key) {
  var keyRegex = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
  if (!key) return false
  if (!(key.length >= 40 && key.length <= 50)) return false
  if (!keyRegex.test(key)) return false

  return nacl.util.decodeBase64(key).length === 32
}
