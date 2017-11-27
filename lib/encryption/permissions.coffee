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

  @flags:
    all      : 1 << ( 2 - 1)
    print    : 1 << ( 3 - 1)
    modify   : 1 << ( 4 - 1)
    copy     : 1 << ( 5 - 1)
    annotate : 1 << ( 6 - 1)
    fill     : 1 << ( 9 - 1)
    extract  : 1 << (10 - 1)
    assembly : 1 << (11 - 1)
    printHQ  : 1 << (12 - 1)

  @parse: (flags = [], revision = 2) ->
    mask = flags.reduce (mem, name) =>
      mem | (@flags[name] ? 0)
    , 0x00

    # Integer objects can be interpreted as binary values in a signed
    # twos-complement form. Since all the reserved high-order flag bits
    # in the encryption dictionary’s P value are required to be 1,
    # the integer value Pshall be specified as a negative integer.
    # For example, assuming revision 2 of the security handler,
    # the value -44 permits printing and copying but disallows modifying
    # the contents and annotations.
    mask |= if revision >= 3 then ~0xFFF else ~0x3F

    buff = Buffer.alloc(4)
    buff.writeInt32BE(mask)
    return buff


module.exports = PDFPermissions
