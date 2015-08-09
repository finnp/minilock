var nacl = require('tweetnacl')
var naclStream = require('nacl-stream')
var BLAKE2s = require('blake2s-js')
var debug = require('debug')('minilock')
var duplexify = require('duplexify')
var pumpify = require('pumpify')
var stream = require('stream')
var block = require('block-stream2')
var getKeyPair = require('./getkeypair')
var util = require('./util')
var createEncryptBodyStream = require('./encryptBodyStream')
var collectTemp = require('./collectTemp')

var MIN_ENCRYPTION_CHUNK_SIZE = 256

function hex (data) {
  return new Buffer(data).toString('hex')
}

module.exports = encryptStream

function encryptStream (email, passphrase, toId, opts) {
  var stream = duplexify()
  getKeyPair(passphrase, email, function (keyPair) {
    encryptStreamWithKeyPair(keyPair, toId, opts, function (err, transform) {
      if (err) return stream.destroy(err)
      transform.on('error', function (err) {
        stream.destroy(err)
      })
      stream.setReadable(transform)
      stream.setWritable(transform)
    })
  })
  return stream
}

function encryptStreamWithKeyPair (keyPair, toIds, opts, cb) {
  opts = opts || {}
  if (!Array.isArray(toIds)) toIds = [toIds]
  var fromId = util.idFromPublicKey(keyPair.publicKey)
  debug('Our miniLock ID is ' + fromId)

  var senderInfo = {
    id: fromId,
    secretKey: keyPair.secretKey
  }

  var fileKey = nacl.randomBytes(32)
  var fileNonce = nacl.randomBytes(16)

  debug('Using file key ' + hex(fileKey))
  debug('Using file nonce ' + hex(fileNonce))

  var chunkSize = MIN_ENCRYPTION_CHUNK_SIZE
  if (opts.chunkSize) {
    if (opts.chunkSize >= MIN_ENCRYPTION_CHUNK_SIZE) {
      chunkSize = opts.chunkSize
    } else {
      return cb(new Error('chunk size too small'))
    }
  }

  var encryptor = naclStream.stream.createEncryptor(fileKey, fileNonce, chunkSize)

  var hash = new BLAKE2s(32)

  var filenameBuffer = new Buffer(256).fill(0)
  filenameBuffer.write(opts.fileName || '')

  var ciphertextStream = createEncryptBodyStream(encryptor, hash)

  ciphertextStream.write(filenameBuffer)

  var addHeader = new stream.Transform()

  var first = false
  addHeader._transform = function (chunk, enc, cb) {
    if (!first) {
      // This is the 32-byte BLAKE2 hash of all the ciphertext.
      var fileHash = hash.digest()
      debug('File hash is ' + hex(fileHash))

      var fileInfo = {
        fileKey: nacl.util.encodeBase64(fileKey),
        fileNonce: nacl.util.encodeBase64(fileNonce),
        fileHash: nacl.util.encodeBase64(fileHash)
      }
      var header = makeHeader(toIds, senderInfo, fileInfo)

      var headerLength = new Buffer(4)
      headerLength.writeUInt32LE(header.length)

      debug('Header length is ' + hex(headerLength))

      var outputHeader = Buffer.concat([
        // The file always begins with the magic bytes 0x6d696e694c6f636b.
        new Buffer('miniLock'), headerLength, new Buffer(header)
      ])
      this.push(outputHeader)
    }
    cb(null, chunk)
  }

  cb(null, pumpify([
    block({size: chunkSize, zeroPadding: false}),
    ciphertextStream,
    collectTemp(util.temporaryFilename()),
    addHeader
  ]))
}

function makeHeader (ids, senderInfo, fileInfo) {
  var ephemeral = nacl.box.keyPair()
  var header = {
    version: 1,
    ephemeral: nacl.util.encodeBase64(ephemeral.publicKey),
    decryptInfo: {}
  }

  debug('Ephemeral public key is ' + hex(ephemeral.publicKey))
  debug('Ephemeral secret key is ' + hex(ephemeral.secretKey))

  ids.forEach(function (id, index) {
    debug('Adding recipient ' + id)

    var nonce = nacl.randomBytes(24)
    var publicKey = util.publicKeyFromId(id)

    debug('Using nonce ' + hex(nonce))

    var decryptInfo = {
      senderID: senderInfo.id,
      recipientID: id,
      fileInfo: fileInfo
    }

    decryptInfo.fileInfo = nacl.util.encodeBase64(nacl.box(
      nacl.util.decodeUTF8(JSON.stringify(decryptInfo.fileInfo)),
      nonce,
      publicKey,
      senderInfo.secretKey
    ))

    decryptInfo = nacl.util.encodeBase64(nacl.box(
      nacl.util.decodeUTF8(JSON.stringify(decryptInfo)),
      nonce,
      publicKey,
      ephemeral.secretKey
    ))

    header.decryptInfo[nacl.util.encodeBase64(nonce)] = decryptInfo
  })

  return JSON.stringify(header)
}
