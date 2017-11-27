###
  http://wwwimages.adobe.com/content/dam/acom/en/devnet/pdf/PDF32000_2008.pdf
  7.6.4.2 Public-Key Encryption Dictionary

  Table 24 – Public-Key security handler user access permissions
  +------+--------------------------------------------------------------------------
  | Bits | Meaning
  +------+--------------------------------------------------------------------------
  |   2  | When set permits change of encryption and enables all other permissions.
  |      |
  |   3  | Print the document (possibly not at the highest quality level, depending
  |      | on whether bit 12 is also set).
  |      |
  |   4  | Modify the contents of the document by operations other than those
  |      | controlled by bits 6, 9, and 11.
  |      |
  |   5  | Copy or otherwise extract text and graphics from the document
  |      | by operations other than that controlled by bit 10.
  |      |
  |   6  | Add or modify text annotations, fill in interactive form fields, and,
  |      | if bit 4 is also set, create or modify interactive form fields
  |      | (including signature fields).
  |      |
  |   9  | (revision >= 3) Fill in existing interactive form fields (including
  |      | signature fields), even if bit 6 is clear.
  |      |
  |  10  | (revision >= 3) Extract text and graphics (in support of accessibility
  |      | to users with disabilities or for other purposes).
  |      |
  |  11  | (revision >= 3) Assemble the document (insert, rotate, or delete pages
  |      | and create bookmarks or thumbnail images), even if bit 4 is clear.
  |      |
  |  12  | (revision >= 3) Print the document to a representation from which
  |      | a faithful digital copy of the PDF content could be generated. When this
  |      | bit is clear (and bit 3 is set), printing is limited to a low- level
  |      | representation of the appearance, possibly of degraded quality.
  +------+--------------------------------------------------------------------------
###

class PDFPermissions

  # Table of permissions
  @table: [
    #-----+------------+-----#
    # Bit | Name       | Rev #
    #-----+------------+-----#
    [  2  , 'all'      , 2   ]
    [  3  , 'print'    , 2   ]
    [  4  , 'modify'   , 2   ]
    [  5  , 'copy'     , 2   ]
    [  6  , 'annotate' , 2   ]
    [  9  , 'fill'     , 3   ]
    [ 10  , 'extract'  , 3   ]
    [ 11  , 'assembly' , 3   ]
    [ 12  , 'printHQ'  , 3   ]
    #-----+------------+-----#
  ]

  # Make key-value map from table of permissions.
  #
  # @param {Function} reducer
  #   Reducer takes items of table row as arguments.
  #   Reducer will be return a key-value pair as array ([key, value]).
  #   If returned value is not array, it will be filtered.
  #
  # @return {Object} - Reduced map of key-value pairs.
  @tableToMap: (reducer) =>
    pairs = @table
      .map (row) -> reducer(row...)
      .filter (pair) -> Array.isArray(pair)
      .reduce ((mem, [ key, val ]) -> mem[key] = val; mem;), {}

  # Generate static key-value maps
  @bitNameMap: @tableToMap (b, n, r) -> [ b, n ]
  @nameBitMap: @tableToMap (b, n, r) -> [ n, b ]
  @nameRevMap: @tableToMap (b, n, r) -> [ n, r ]
  @nameIntMap: @tableToMap (b, n, r) -> [ n, 1 << b - 1 ]


  # Convert list of permission names to byte buffer
  @permsToBuffer: (perms = [], rev = 2) ->
    # Integer objects can be interpreted as binary values in a signed
    # twos-complement form. Since all the reserved high-order flag bits
    # in the encryption dictionary’s P value are required to be 1,
    # the integer value Pshall be specified as a negative integer.
    # For example, assuming revision 2 of the security handler,
    # the value -44 permits printing and copying but disallows modifying
    # the contents and annotations.
    mask = switch
      when rev >= 3 then ~0xFFF # 12 bits
      when rev == 2 then ~0x3F  #  6 bits
      else throw new Error('Invalid revision')

    # Check revisions
    ignored = perms
      .filter (n) => (@nameRevMap[n] ? 0) > rev

    least = ignored
      .map (n) => @nameRevMap[n] ? 0
      .reduce ((m, r) => Math.max(m, r)), 0

    if ignored.length > 0
      err = new Error "
        #{ignored.join(', ')} permissions will be ignored.
        Need revision #{least} or greater.
      "
      console.warn err.stack

    # Compute bit mask for permissions
    bits = mask | perms
      .map (n) => @nameIntMap[n] ? 0
      .reduce ((s, i) => s | i), 0

    buffer = Buffer.alloc(4)
    buffer.writeInt32BE(bits)
    return buffer


  # Convert number or byte buffer to list of permission names
  @bufferToPerms: (buffer, rev = 2) ->
    int = switch
      when 'number' is typeof buffer then buffer
      when buffer instanceof Buffer  then buffer.readInt32BE()
      else throw new Error('Invalid type of buffer. Must be a number or byte buffer.')

    return @table
      .filter ([b, n, r]) => rev >= r
      .filter ([b, n, r]) => int & (@nameIntMap[n] ? 0)
      .map ([b, n, r]) => n


module.exports = PDFPermissions
