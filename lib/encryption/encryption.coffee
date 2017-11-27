Crypto = require './crypto'
Security = require './security'
Permissions = require './permissions'


# http://wwwimages.adobe.com/content/dam/acom/en/devnet/pdf/PDF32000_2008.pdf
# 7.6 Encryption
class PDFEncryption

  AES_SALT = [0x73, 0x41, 0x6C, 0x54]

  constructor: (@options) ->
    # options contains:
    #   fileId, filter, version, algorithm,
    #   keyLength, revision, permissions,
    #   ownerPassword, userPassword

    o = @options

    @useAES   = o.algorithm == 'AES'
    @permBuff = Permissions.permsToBuffer o.permissions, o.revision
    @permInt  = @permBuff.readInt32BE()

    @ownerKey = Security.computeOwnerKey o.ownerPassword, o.userPassword,
      fileId   : o.fileId
      revision : o.revision
      length   : o.keyLength
      perms    : @permBuff

    @userKey = Security.computeUserKey o.userPassword,
      fileId   : o.fileId
      revision : o.revision
      length   : o.keyLength
      perms    : @permBuff
      ownerKey : @ownerKey

    @encryptionKey = Security.computeEncryptionKey o.userPassword,
      fileId   : o.fileId
      revision : o.revision
      length   : o.keyLength
      perms    : @permBuff
      ownerKey : @ownerKey


  ###
  # 7.6.2 General Encryption Algorithm
  # Algorithm 1: Encryption of data using the RC4 or AES algorithms
  ###
  createEncryptor: (id, gen) ->
    # b) For all strings and streams without crypt filter specifier;
    #    treating the object number and generation number as binary
    #    integers, extend the original n-byte encryption key to n + 5
    #    bytes by appending the low-order 3 bytes of the object number
    #    and the low-order 2 bytes of the generation number in that order,
    #    low-order byte first. (n is 5 unless the value of V in the
    #    encryption dictionary is greater than 1, in which case
    #    n is the value of Length divided by 8.)
    #
    #    If using the AES algorithm, extend the encryption key an additional
    #    4 bytes by adding the value “sAlT”, which corresponds to the
    #    hexadecimal values 0x73, 0x41, 0x6C, 0x54. (This addition is done
    #    for backward compatibility and is not intended to provide additional
    #    security.)
    baseSize = @encryptionKey.length
    tailSize = if @useAES then 9 else 5
    fullSize = baseSize + tailSize

    oidBuff = Buffer.alloc(4); oidBuff.writeInt32LE(id)
    genBuff = Buffer.alloc(4); genBuff.writeInt32LE(gen)

    key = Buffer.alloc fullSize
      .fill @encryptionKey, 0           , baseSize
      .fill oidBuff       , baseSize    , baseSize + 3
      .fill genBuff       , baseSize + 3, baseSize + 5

    if @useAES
      key.fill AES_SALT, baseSize + 5, baseSize + 9

    # c) Initialize the MD5 hash function and pass the result of step (b)
    #    as input to this function.
    key = Crypto.hash.MD5(key)

    # d) Use the first (n + 5) bytes, up to a maximum of 16, of the output
    #    from the MD5 hash as the key for the RC4 or AES symmetric key
    #    algorithms, along with the string or stream data to be encrypted.
    #
    #    If using the AES algorithm, the Cipher Block Chaining (CBC) mode,
    #    which requires an initialization vector, is used. The block size
    #    parameter is set to 16 bytes, and the initialization vector
    #    is a 16-byte random number that is stored as the first 16 bytes
    #    of the encrypted stream or string.
    #
    #    The output is the encrypted data to be stored in the PDF file.
    key = key.slice 0, Math.min(16, fullSize)
    encryptor = if @useAES then Crypto.encrypt.AES else Crypto.encrypt.RC4
    return encryptor(key)


module.exports = PDFEncryption
