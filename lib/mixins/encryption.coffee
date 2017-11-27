Permissions = require '../encryption/permissions'
Encryption = require '../encryption/encryption'


warnStack = (message) ->
  err = new Error message
  console.warn err.stack

module.exports =
  initEncryption: ->
    @encryption = false

    # The name of the preferred security handler for this document. It shall
    # be the name of the security handler that was used to encrypt the document.
    # Supported only standard password-based security handler.
    @_encryptionFilter = 'Standard'

    # A code specifying the algorithm to be used in encrypting the document
    #   1 - Encryption of data using the RC4 or AES algorithms,
    #       with an encryption key length of 40 bits.
    #   2 - Encryption of data using the RC4 or AES algorithms,
    #       with an encryption key length of 40 or greater bits.
    #   3, 4 - Not supported.
    @_encryptionVersion = 1

    # Specifying the algorithm to be used in encrypting the document: RC4 or AES
    @_encryptionAlgorithm = 'RC4'

    # The length of the encryption key, in bits. The value shall be a multiple
    # of 8, in the range 40 to 128.
    @_encryptionKeyLength = 40

    # A number specifying which revision of the standard security
    # handler shall be used to interpret this dictionary
    #   2 - if the document is encrypted with a V value less than 2
    #       and does not have any of the access permissions set to 0
    #       that are designated security handlers of revision 3 or greater
    #   3 - if the document is encrypted with a V value of 2 or 3,
    #       or has any “Security handlers of revision 3 or greater” access
    #       permissions set to 0
    #   4 - Not supported
    @_encryptionRevision = 2

    # A set of flags specifying which operations shall be permitted
    # when the document is opened with user access
    @_encryptionPermissions = []

    # A 32-byte string, based on both the owner and user passwords,
    # that shall be used in computing the encryption key and in determining
    # whether a valid owner password was entered.
    @_encryptionOwnerPassword = null

    # A 32-byte string, based on the user password, that shall be
    # used in determining whether to prompt the user for a password and, if so,
    # whether a valid user or owner password was entered.
    @_encryptionUserPassword = null


    # Parse and validate user options
    if @options.encryption
      { version, revision, key, permissions, owner, user } = @options.encryption

      valid =
        ver: false
        key: false
        rev: false

      # Validate version
      if typeof version is 'number' and 1 <= version <= 2
        valid.ver = true
        @_encryptionVersion = version
      else if version?
        warnStack "
          Encryption version #{version} is not supported.
          Will be used default version: #{@_encryptionVersion}.
        "

      # Validate key
      # Examples: 40, 128, RC4, AES, RC4-40, AES-128, ...
      # Default: RC4-40
      # keyre = /^(?:(RC4|AES)-)?(\d+)?$/i
      keyre = /^(?:(RC4)-)?(\d+)?$/i
      if key? and keyre.test String(key)
        [key, alg, len] = String(key).match keyre
        valid.key = alg? or len?
        if alg?
          @_encryptionAlgorithm = alg.toUpperCase()
        if len?
          len = Number len
          if (40 <= len <= 128) and (len % 8 == 0)
            @_encryptionKeyLength = len
          else
            valid.key = false
            warnStack "
              Encryption key length #{len} is invalid.
              The value shall be a multiple of 8, in the range 40 to 128.
              Will be used default value: #{@_encryptionKeyLength}.
            "

      # Validate version and key length
      if @_encryptionVersion < 2 and 40 < @_encryptionKeyLength
        @_encryptionVersion = 2
        if valid.ver
          warnStack "
            For encryption key length #{@_encryptionKeyLength} the version
            value shall be greater then 1. Will be used version
            #{@_encryptionVersion}.
          "

      # Validate revision
      if typeof revision is 'number' and 2 <= revision <= 3
        valid.rev = true
        @_encryptionRevision = revision
      else if revision?
        warnStack "
          Encryption revision #{revision} is not supported.
          Will be used default revision: #{@_encryptionRevision}.
        "

      # Validate permissions
      if Array.isArray permissions
        @_encryptionPermissions = permissions.filter (p) -> Permissions.nameRevMap[p]?
        ignored = permissions.filter (p) -> not Permissions.nameRevMap[p]?
        revs = permissions.map (p) -> Permissions.nameRevMap[p] || 0
        need = Math.max 0, revs...
        if need > @_encryptionRevision
          @_encryptionRevision = need
          if valid.rev
            warnStack "
              The passed permissions require the revision #{need}
            "
        if ignored.length
          warnStack "
            Following permissions #{ignored.join(', ')} is invalid
            and will be ignored.
          "

      # Validate version and revision
      if @_encryptionVersion < 2 and 2 < @_encryptionRevision
        @_encryptionRevision = 3
        if valid.rev
          warnStack "
            For encryption version #{@_encryptionVersion} the revision
            value shall be greater then 2. Will be used revision
            #{@_encryptionRevision}.
          "

      @_encryptionOwnerPassword = owner ? ''
      @_encryptionUserPassword = user ? ''

      if owner? or user?
        @encryption = new Encryption
          fileId        : @fileId
          filter        : @_encryptionFilter
          version       : @_encryptionVersion
          algorithm     : @_encryptionAlgorithm
          keyLength     : @_encryptionKeyLength
          revision      : @_encryptionRevision
          permissions   : @_encryptionPermissions
          ownerPassword : @_encryptionOwnerPassword
          userPassword  : @_encryptionUserPassword

  _getEncryptionRef: ->
    return if not @encryption
    return @ref
      Filter : @_encryptionFilter
      Length : @_encryptionKeyLength
      V      : @_encryptionVersion
      R      : @_encryptionRevision
      P      : @encryption.permInt
      O      : @encryption.ownerKey
      U      : @encryption.userKey

  createEncryptor: (id, gen) ->
    @encryption.createEncryptor id, gen
