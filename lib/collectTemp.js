// duplex stream that collects input chunks to disk, waits for the last to arrive,
// then starts writing to the output

var fs = require('fs')
var duplexify = require('duplexify')

module.exports = collectTemp

function collectTemp (tempFileName) {
  var duplex = duplexify()
  var fileWrite = fs.createWriteStream(tempFileName)
  duplex.setWritable(fileWrite)
  fileWrite.on('finish', function () {
    var fileRead = fs.createReadStream(tempFileName)
    fileRead.on('end', function () {
      fs.unlink(tempFileName)
    })
    duplex.setReadable(fileRead)
  })
  return duplex
}

