var stream = require('stream')

module.exports = encryptBodyStream

function encryptBodyStream (encryptor, hash) {
  var encryptChunks = new stream.Transform()
  encryptChunks._transform = transform
  encryptChunks._flush = flush

  function transform (chunk, enc, cb) {
    var encryptedChunk = encryptor.encryptChunk(new Uint8Array(chunk || []), false)
    this.push(new Buffer(encryptedChunk))
    if (hash) hash.update(encryptedChunk)
    cb()
  }

  function flush (cb) {
    // encrypting one last empty chunk
    var encryptedChunk = encryptor.encryptChunk(new Uint8Array([]), true)
    if (hash) hash.update(encryptedChunk)
    encryptor.clean()
    this.push(new Buffer(encryptedChunk))
    cb()
  }
  return encryptChunks
}
