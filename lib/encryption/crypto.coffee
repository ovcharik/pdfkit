# Helpers for crypto-js

Crypto = require 'crypto-js'
WordArray = Crypto.lib.WordArray


bufferToWordArray = b2wa = (buffer = '', args...) ->
  if buffer not instanceof Buffer
    buffer = Buffer.from(buffer, args...)
  view = Uint8Array.from(buffer)
  WordArray.create(view)

wordArrayToBuffer = wa2b = (array = {}) ->
  view = Uint32Array.from(array.words ? [])
  Buffer.from(view.buffer).swap32()


wrapHash = (hash) -> (msg = '', args...) ->
  array = b2wa msg, args...
  wa2b hash array

wrapHasher = (hasher) -> (data = '', args...) ->
  return wa2b hasher.create().finalize b2wa data, args... if data
  hasher    : hasher.create()
  update    : (data) -> @hasher.update b2wa data; return @
  end       : (data) -> wa2b @hasher.finalize b2wa data
  sum       : (data) -> @end data

wrapEncryptor = (encryptor) -> (key = '', args...) ->
  buffer    : WordArray.create()
  encryptor : encryptor.createEncryptor b2wa key, args...
  reset     : (data) -> @encryptor.reset data; return @
  write     : (data) -> @buffer.concat @encryptor.process b2wa data; return @
  end       : (data) -> wa2b @buffer.concat @encryptor.finalize b2wa data


module.exports =
  Crypto       : Crypto
  WordArray    : WordArray
  MD5Hasher    : wrapHasher(Crypto.algo.MD5)
  RC4Encryptor : wrapEncryptor(Crypto.algo.RC4)
