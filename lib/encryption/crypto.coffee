# Helpers for crypto-js

import Crypto from 'crypto-js'

WordArray = Crypto.lib.WordArray

bufferToWordArray = b2wa = (buffer = '', args...) ->
  if buffer not instanceof Buffer
    buffer = Buffer.from(buffer, args...)
  view = Uint8Array.from(buffer)
  WordArray.create(view)

wordArrayToBuffer = wa2b = (array = {}) ->
  view = Uint32Array.from(array.words ? [])
  length = array.sigBytes ? null
  Buffer.from(view.buffer).swap32().slice(0, length)

randomBytes = (length) ->
  wa2b WordArray.random length

wrapHasher = (hasher) -> (data = '', args...) ->
  return wa2b hasher.create().finalize b2wa data, args... if data
  hasher    : hasher.create()
  update    : (data) -> @hasher.update b2wa data; return @
  end       : (data) -> wa2b @hasher.finalize b2wa data
  sum       : (data) -> @end data

wrapEncryptor = (encryptor, options = {}) -> (key = '', args...) ->
  buffer    : WordArray.create()
  encryptor : encryptor.createEncryptor b2wa(key, args...), options?() ? options
  reset     : (data) -> @encryptor.reset data; return @
  write     : (data) -> @buffer.concat @encryptor.process b2wa data; return @
  end       : (data) -> wa2b @buffer.concat @encryptor.finalize b2wa data


export { randomBytes }

export hash =
  MD5: wrapHasher Crypto.algo.MD5

export encrypt =
  RC4: wrapEncryptor Crypto.algo.RC4
  AES: wrapEncryptor Crypto.algo.AES, () ->
    iv     : WordArray.random 32
    mode   : Crypto.mode.CBC
    padding: Crypto.pad.Pkcs7
