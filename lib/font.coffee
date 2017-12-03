import fontkit from 'fontkit'

import StandardFont from './font/standard'
import EmbeddedFont from './font/embedded'

class PDFFont
  @open: (document, src, family, id) ->
    if typeof src is 'string'
      if StandardFont.isStandardFont src
        return new StandardFont document, src, id
        
      font = fontkit.openSync src, family
                
    else if Buffer.isBuffer(src)
      font = fontkit.create src, family
      
    else if src instanceof Uint8Array
      font = fontkit.create new Buffer(src), family
      
    else if src instanceof ArrayBuffer
      font = fontkit.create new Buffer(new Uint8Array(src)), family
      
    if not font?
      throw new Error 'Not a supported font format or standard PDF font.'
      
    return new EmbeddedFont document, font, id

export default PDFFont
