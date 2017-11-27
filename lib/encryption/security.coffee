Crypto = require './crypto'
Permissions = require './permissions'


# http://wwwimages.adobe.com/content/dam/acom/en/devnet/pdf/PDF32000_2008.pdf
# 7.6 Encryption
class PDFSecurity

  DEFAULT_OPTIONS =
    fileId   : Buffer.alloc 0
    revision : 2
    length   : 40
    perms    : Buffer.from [ 0xFF, 0xFF, 0xFF, 0xFF ]
    ownerKey : null

  mergeOptions = (options = {}) ->
    Object.assign({}, DEFAULT_OPTIONS, options)


  KEY_LENGTH = 32

  PADDIGN = Buffer.from [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
  ]

  createBufferWithPadding = (str = '') ->
    buffer = Buffer.alloc(KEY_LENGTH)
    offset = buffer.write(str)
    return buffer.fill(PADDIGN, offset)


  ###
  # 7.6.3.3 Encryption Key Algorithm
  # Algorithm 2: Computing an encryption key
  ###
  @computeEncryptionKey: (pass = '', options = {}) ->
    opts = mergeOptions(options)
    if not Number.isInteger(opts.revision) or opts.revision < 2
      throw new Error('Invalid revision version')
    if opts.revision != 2 and opts.length % 8
      throw new Error('Invalid key length')
    if not opts.ownerKey
      throw new Error('Invalid owner key')
    if not opts.fileId?[0]
      throw new Error('Invalid file identifier')

    # a) Pad or truncate the password string to exactly 32 bytes.
    #    If the password string is more than 32 bytes long, use
    #    only its first 32 bytes; if it is less than 32 bytes long,
    #    pad it by appending the required number of additional bytes
    #    from the beginning of the following padding string:
    #    <PADDIGN>
    #    That is, if the password string is n bytes long, append
    #    the first 32 - n bytes of the padding string to the end
    #    of the password string. If the password string is empty
    #    (zero-length), meaning there is no user password, substitute
    #    the entire padding string in its place.
    ownBuff = createBufferWithPadding(pass)

    # b) Initialize the MD5 hash function and pass the result
    #    of step (a) as input to this function.
    ownHash = Crypto.hash.MD5().update(ownBuff)

    # c) Pass the value of the encryption dictionary’s O entry to the
    #    MD5 hash function. ("Algorithm 3: Computing the encryption
    #    dictionary’s O (owner password) value" shows how the O value
    #    is computed.)
    ownHash = ownHash.update(opts.ownerKey)

    # d) Convert the integer value of the P entry to a 32-bit unsigned
    #    binary number and pass these bytes to the MD5 hash function,
    #    low-order byte first.
    ownHash = ownHash.update Buffer.from(opts.perms).swap32()

    # e) Pass the first element of the file’s file identifier array
    #    (the value of the ID entry in the document’s trailer dictionary;
    #    see Table 15) to the MD5 hash function.
    ownHash = ownHash.update(opts.fileId)

    # f) (Security handlers of revision 4 or greater) If document metadata
    #    is not being encrypted, pass 4 bytes with the value 0xFFFFFFFF
    #    to the MD5 hash function.
    if opts.revision >= 4 # TODO: condition
      ownHash = ownHash.update Buffer.from [0...4].map -> 0xFF

    # g) Finish the hash.
    ownHash = ownHash.end()

    # h) (Security handlers of revision 3 or greater) Do the following
    #    50 times: Take the output from the previous MD5 hash and pass
    #    the first n bytes of the output as input into a new MD5 hash,
    #    where n is the number of bytes of the encryption key as defined
    #    by the value of the encryption dictionary’s Length entry.
    if opts.revision >= 3
      size = opts.length / 8
      for i in [0...50]
        ownHash = Crypto.hash.MD5 ownHash.slice 0, size

    # i) Set the encryption key to the first n bytes of the output from
    #    the final MD5 hash, where n shall always be 5 for security handlers
    #    of revision 2 but, for security handlers of revision 3 or greater,
    #    shall depend on the value of the encryption dictionary’s Length entry.
    keySize = if opts.revision > 2 then opts.length / 8 else 5
    encryptionKey = ownHash.slice 0, keySize
    return encryptionKey


  ###
  # 7.6.3.4 Password Algorithms
  # Algorithm 3: Computing the encryption dictionary’s O (owner password) value
  ###
  @computeOwnerKey: (owner = '', user = '', options = {}) ->
    opts = mergeOptions(options)
    if not Number.isInteger(opts.revision) or opts.revision < 2
      throw new Error('Invalid revision version')
    if opts.revision != 2 and opts.length % 8
      throw new Error('Invalid key length')

    # a) Pad or truncate the owner password string as described
    #    in step (a) of "Algorithm 2: Computing an encryption key".
    #    If there is no owner password, use the user password instead.
    ownBuff = createBufferWithPadding(owner || user)

    # b) Initialize the MD5 hash function and pass the result
    #    of step (a) as input to this function.
    ownHash = Crypto.hash.MD5(ownBuff)

    # c) (Security handlers of revision 3 or greater)
    #    Do the following 50 times: Take the output from the previous
    #    MD5 hash and pass it as input into a new MD5 hash.
    if opts.revision >= 3
      for i in [1..50]
        ownHash = Crypto.hash.MD5(ownHash)

    # d) Create an RC4 encryption key using the first n bytes
    #    of the output from the final MD5 hash, where n shall always
    #    be 5 for security handlers of revision 2 but, for security
    #    handlers of revision 3 or greater, shall depend on the value
    #    of the encryption dictionary’s Length entry.
    keySize = if opts.revision != 2 then opts.length / 8 else 5
    keyBase = ownHash.slice(0, keySize)

    # e) Pad or truncate the user password string as described
    #    in step (a) of "Algorithm 2: Computing an encryption key".
    usrBuff = createBufferWithPadding(user)

    # f) Encrypt the result of step (e), using an RC4 encryption
    #    function with the encryption key obtained in step (d).
    ownKey = Crypto.encrypt.RC4(keyBase).end(usrBuff)

    # g) (Security handlers of revision 3 or greater) Do the following
    #    19 times: Take the output from the previous invocation of the RC4
    #    function and pass it as input to a new invocation of the function;
    #    use an encryption key generated by taking each byte of the
    #    encryption key obtained in step (d) and performing an XOR
    #    (exclusive or) operation between that byte and the single-byte
    #    value of the iteration counter (from 1 to 19).
    if opts.revision >= 3
      for i in [1..19]
        keyBuff = keyBase.map (v) -> v ^ i
        ownKey = Crypto.encrypt.RC4(keyBuff).end(ownKey)

    # h) Store the output from the final invocation of the RC4 function
    #    as the value of the O entry in the encryption dictionary.
    return ownKey


  ###
  # 7.6.3.4 Password Algorithms
  # Algorithm 4: Computing the encryption dictionary’s U (user password)
  # value (Security handlers of revision 2)
  ###
  @computeUserKeyRev2: (user = '', options = {}) ->
    opts = mergeOptions(options)
    if not Number.isInteger(opts.revision) or opts.revision != 2
      throw new Error('Invalid revision version')

    # a) Create an encryption key based on the user password string,
    #    as described in "Algorithm 2: Computing an encryption key".
    usrBuff = @computeEncryptionKey(user, options)

    # b) Encrypt the 32-byte padding string shown in step (a)
    #    of "Algorithm 2: Computing an encryption key", using an RC4
    #    encryption function with the encryption key from the preceding step.
    usrKey = Crypto.encrypt.RC4(usrBuff).end(PADDIGN)

    # c) Store the result of step (b) as the value of the U entry
    #    in the encryption dictionary
    return usrKey


  ###
  # 7.6.3.4 Password Algorithms
  # Algorithm 5: Computing the encryption dictionary’s U (user password)
  # value (Security handlers of revision 3 or greater)
  ###
  @computeUserKeyRev3: (user = '', options = {}) ->
    opts = mergeOptions(options)
    if not Number.isInteger(opts.revision) or opts.revision < 3
      throw new Error('Invalid revision version')
    if not opts.fileId?[0]
      throw new Error('Invalid file identifier')

    # a) Create an encryption key based on the user password string,
    #    as described in "Algorithm 2: Computing an encryption key".
    keyBase = @computeEncryptionKey(user, options)

    # b) Initialize the MD5 hash function and pass the 32-byte padding
    #    string shown in step (a) of "Algorithm 2: Computing an encryption
    #    key" as input to this function.
    usrHash = Crypto.hash.MD5().update(PADDIGN)

    # c) Pass the first element of the file’s file identifier array
    #    (the value of the ID entry in the document’s trailer dictionary;
    #    see Table 15) to the hash function and finish the hash.
    usrHash = usrHash.update(opts.fileId)
    usrHash = usrHash.end()

    # d) Encrypt the 16-byte result of the hash, using an RC4 encryption
    #    function with the encryption key from step (a).
    usrKey = Crypto.encrypt.RC4(keyBase).end(usrHash)

    # e) Do the following 19 times: Take the output from the previous
    #    invocation of the RC4 function and pass it as input to a new invocation
    #    of the function; use an encryption key generated by taking each byte
    #    of the original encryption key obtained in step (a) and performing an XOR
    #    (exclusive or) operation between that byte and the single-byte value
    #    of the iteration counter (from 1 to 19).
    for i in [1..19]
      keyBuff = keyBase.map (v) -> v ^ i
      usrKey = Crypto.encrypt.RC4(keyBuff).end(usrKey)

    # f) Append 16 bytes of arbitrary padding to the output from the final
    #    invocation of the RC4 function and store the 32-byte result as the value
    #    of the U entry in the encryption dictionary.
    usrKey = Buffer.alloc(32)
      .fill usrKey, 0, usrKey.length
      .fill Buffer.from('0122456a91bae5134273a6db134c87c4', 'hex'), 16, 32
    return usrKey


  @computeUserKey: (user = '', options = {}) ->
    opts = mergeOptions(options)
    switch
      when opts.revision == 2 then @computeUserKeyRev2(user, options)
      when opts.revision >= 3 then @computeUserKeyRev3(user, options)
      else throw new Error('Invalid revision version')

module.exports = PDFSecurity
