var nacl = require('tweetnacl')
var naclStream = require('nacl-stream')
var BLAKE2s = require('blake2s-js')
var debug = require('debug')('minilock')
var duplexify = require('duplexify')
var stream = require('stream')
var getKeyPair = require('./getkeypair')
var util = require('./util')

var MIN_ENCRYPTION_CHUNK_SIZE = 256

function hex (data) {
  return new Buffer(data).toString('hex')
}

module.exports.encryptStream = encryptStream

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

  var transform = new stream.Transform()

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

  // This is where the encrypted chunks go.
  var encrypted = []

  var filenameBuffer = new Buffer(256).fill(0)
  filenameBuffer.write(opts.fileName || '')

  encryptChunk(filenameBuffer, encryptor, encrypted, hash)

  var inputByteCount = 0

  transform._transform = function (chunk, enc, cb) {
    inputByteCount += chunk.length
    encryptChunk(chunk, encryptor, encrypted, hash, chunkSize)
    cb()
  }

  transform._flush = function (cb) {
    encryptChunk(null, encryptor, encrypted, hash, chunkSize)
    encryptor.clean()

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

    encrypted.forEach(function (chunk) {
      this.push(chunk)
    }.bind(this))
    cb()
  }

  cb(null, transform)
}

function encryptChunk (chunk, encryptor, output, hash, chunkSize) {
  if (chunk && chunk.length > chunkSize) {
    // slice chunk
    for (var i = 0; i < chunk.length; i += chunkSize) {
      encryptChunk(chunk.slice(i, i + chunkSize),
        encryptor, output, hash, chunkSize)
    }
  } else {
    chunk = encryptor.encryptChunk(new Uint8Array(chunk || []), !chunk)

    debug('Encrypted chunk ' + hex(chunk))

    if (Array.isArray(output)) output.push(new Buffer(chunk))
    else output.write(new Buffer(chunk))

    if (hash) hash.update(chunk)
  }
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
