###
PDFReference - represents a reference to another object in the PDF object heirarchy
By Devon Govett
###

import zlib from 'zlib'
import stream from 'stream'
import PDFObject from './object'

class PDFReference extends stream.Writable
  constructor: (@document, @id, @data = {}) ->
    super decodeStrings: no

    @gen = 0
    @deflate = null
    @compress = @document.compress and not @data.Filter
    @encrypt = @document.encryption and not @data.Filter
    @uncompressedLength = 0
    @chunks = []

  initDeflate: ->
    @data.Filter = 'FlateDecode'

    @deflate = zlib.createDeflate()
    @deflate.on 'data', (chunk) =>
      @chunks.push chunk
      @data.Length += chunk.length

    @deflate.on 'end', @finalize

  initEncypt: ->
    return if not @encrypt
    @encryptor = @document.createEncryptor(@id, @gen)
    @encrypt = (data) =>
      @document.createEncryptor(@id, @gen).end(data)

  _write: (chunk, encoding, callback) ->
    unless Buffer.isBuffer(chunk)
      chunk = new Buffer(chunk + '\n', 'binary')

    @uncompressedLength += chunk.length
    @data.Length ?= 0

    if @compress
      @initDeflate() if not @deflate
      @deflate.write chunk
    else
      @chunks.push chunk
      @data.Length += chunk.length

    callback()

  end: (chunk) ->
    super chunk

    if @deflate
      @deflate.end()
    else
      @finalize()

  finalize: =>
    @initEncypt() if @encrypt

    @offset = @document._offset

    @document._write "#{@id} #{@gen} obj"
    @document._write PDFObject.convert(@data, @encrypt)

    if @chunks.length
      @document._write 'stream'
      for chunk in @chunks
        if @encryptor
          @encryptor.write chunk
        else
          @document._write chunk

      if @encryptor
        @document._write @encryptor.end()
        @encryptor.reset() # free up memory

      @chunks.length = 0 # free up memory
      @document._write '\nendstream'

    @document._write 'endobj'
    @document._refEnd(this)

  toString: ->
    return "#{@id} #{@gen} R"

export default PDFReference
