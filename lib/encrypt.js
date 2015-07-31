var nacl = require('tweetnacl')
var naclStream = require('nacl-stream')
var BLAKE2s = require('blake2s-js')
var debug = require('debug')('minilock')
var stream = require('stream')
var getKeyPair = require('./getkeypair')
var util = require('./util')

var ENCRYPTION_CHUNK_SIZE = 256

function hex (data) {
  return new Buffer(data).toString('hex')
}

module.exports.encryptStream = encryptStream

function encryptStream (email, passphrase, toId, cb) {
  getKeyPair(passphrase, email, function (keyPair) {
    cb(null, encryptStreamWithKeyPair(keyPair, toId))
  })
}

function encryptStreamWithKeyPair (keyPair, toIds) {
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

  var encryptor = naclStream.stream.createEncryptor(fileKey, fileNonce, ENCRYPTION_CHUNK_SIZE)

  var hash = new BLAKE2s(32)

  // This is where the encrypted chunks go.
  var encrypted = []

  var filenameBuffer = new Buffer(256).fill(0) // TODO: Add filename here

  encryptChunk(filenameBuffer, encryptor, encrypted, hash)

  var inputByteCount = 0

  var transform = new stream.Transform()

  transform._transform = function (chunk, enc, cb) {
    inputByteCount += chunk.length
    encryptChunk(chunk, encryptor, encrypted, hash)
    cb()
  }

  transform._flush = function (cb) {
    encryptChunk(null, encryptor, encrypted, hash)
    encryptor.clean()

    // This is the 32-byte BLAKE2 hash of all the ciphertext.
    var fileHash = hash.digest()
    debug('File hash is ' + hex(fileHash))

    var fileInfo = {
      fileKey: nacl.util.encodeBase64(fileKey),
      fileNonce: nacl.util.encodeBase64(fileNonce),
      fileHash: nacl.util.encodeBase64(fileHash)
    }

    // TODO: Include self, multiple recipients
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

  return transform
}

function encryptChunk (chunk, encryptor, output, hash) {
  if (chunk && chunk.length > ENCRYPTION_CHUNK_SIZE) {
    // slice chunk
    for (var i = 0; i < chunk.length; i += ENCRYPTION_CHUNK_SIZE) {
      encryptChunk(chunk.slice(i, i + ENCRYPTION_CHUNK_SIZE),
        encryptor, output, hash)
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

  // TODO: Should the this be stringified here?
  return JSON.stringify(header)
}