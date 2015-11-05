# \ParagonIE\Halite\KeyFactory (abstract)

A factory class responsible for the creation and persistence of cryptography
keys.

## Methods

### public static function generateAuthenticationKey(`&$secret_key = null`) : [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Generate an authentication key (symmetric-key cryptography).
    
### public static function generateEncryptionKey(`&$secret_key = null`) : [`EncryptionKey`](Symmetric/EncryptionKey.md)

Generate an encryption key (symmetric-key cryptography).

### public static function generateEncryptionKeyPair(`&$secret_key = null`) : [`EncryptionKeyPair`](EncryptionKeyPair.md)

Generate a key pair for public key encryption.

### public static function generateSignatureKeyPair(`&$secret_key = null`) : [`SignatureKeyPair`](SignatureKeyPair.md)

Generate a key pair for public key digital signatures.

### public static function deriveAuthenticationKey(`string $password`, `string $salt`) : [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Derive a symmetric authentication key from a password and salt.
    
### public static function deriveEncryptionKey(`string $password`, `string $salt`) : [`EncryptionKey`](Symmetric/EncryptionKey.md)

Derive a symmetric encryption key from a password and salt.

### public static function deriveEncryptionKeyPair(`string $password`, `string $salt`) : [`EncryptionKeyPair`](EncryptionKeyPair.md)

Derive an asymmetric encryption key pair from a password and salt.

### public static function generateSignatureKeyPair(`string $password`, `string $salt`) : [`SignatureKeyPair`](SignatureKeyPair.md)

Derive an asymmetric signature key pair from a password and salt.

### public static function loadAuthenticationKey(`string $filePath`) : [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Load an `AuthenticationKey` from a file.

### public static function loadEncryptionKey(`string $filePath`) : [`EncryptionKey`](Symmetric/EncryptionKey.md)

Load an `EncryptionKey` from a file.

### public static function loadEncryptionKeyPair(`string $filePath`) : [`EncryptionKeyPair`](EncryptionKeyPair.md)

Load an `EncryptionKeyPair` from a file.

### public static function loadSignatureKeyPair(`string $filePath`) : [`SignatureKeyPair`](SignatureKeyPair.md)

Load an `SignatureKeyPair` from a file.

### public static function save(`Key|KeyPair $key`, `string $filename = ''`)

Save a key to a file.
