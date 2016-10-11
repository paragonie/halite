# KeyFactory (abstract)

**Namespace**: `\ParagonIE\Halite`

A factory class responsible for the creation and persistence of cryptography
keys.

## Methods

### `generateAuthenticationKey()`

> `public static` generateAuthenticationKey(`&$secret_key = null`): [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Generate an authentication key (symmetric-key cryptography).
    
### `generateEncryptionKey()`

> `public static` generateEncryptionKey(`&$secret_key = null`): [`EncryptionKey`](Symmetric/EncryptionKey.md)

Generate an encryption key (symmetric-key cryptography).

### `generateEncryptionKeyPair()`

> `public static` generateEncryptionKeyPair(`&$secret_key = null`): [`EncryptionKeyPair`](EncryptionKeyPair.md)

Generate a key pair for public key encryption.

### `generateSignatureKeyPair()`

> `public static` generateSignatureKeyPair(`&$secret_key = null`): [`SignatureKeyPair`](SignatureKeyPair.md)

Generate a key pair for public key digital signatures.

### `deriveAuthenticationKey()`

> `public static` deriveAuthenticationKey(`HiddenString $password`, `string $salt`, `string $level`): [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Derive a symmetric authentication key from a password and salt.

Acceptable values for `$level`:

* `KeyFactory::INTERACTIVE` - default
* `KeyFactory::MODERATE` - takes one to two seconds (depending on hardware)
* `KeyFactory::SENSITIVE` - takes several seconds; recommended for mission critical cryptography keys
    
### `deriveEncryptionKey()`

> `public static` deriveEncryptionKey(`HiddenString $password`, `string $salt`, `string $level`): [`EncryptionKey`](Symmetric/EncryptionKey.md)

Derive a symmetric encryption key from a password and salt.

### `deriveEncryptionKeyPair()`

> `public static` deriveEncryptionKeyPair(`HiddenString $password`, `string $salt`, `string $level`): [`EncryptionKeyPair`](EncryptionKeyPair.md)

Derive an asymmetric encryption key pair from a password and salt.

### `deriveSignatureKeyPair()`

> `public static` deriveSignatureKeyPair(`HiddenString $password`, `string $salt`, `string $level`): [`SignatureKeyPair`](SignatureKeyPair.md)

Derive an asymmetric signature key pair from a password and salt.

### `loadAuthenticationKey()`

> `public static` loadAuthenticationKey(`string $filePath`): [`AuthenticationKey`](Symmetric/AuthenticationKey.md)

Load an `AuthenticationKey` from a file.

### `loadEncryptionKey()`

> `public static` loadEncryptionKey(`string $filePath`): [`EncryptionKey`](Symmetric/EncryptionKey.md)

Load an `EncryptionKey` from a file.

### `loadEncryptionKeyPair()`

> `public static` loadEncryptionKeyPair(`string $filePath`): [`EncryptionKeyPair`](EncryptionKeyPair.md)

Load an `EncryptionKeyPair` from a file.

### `loadSignatureKeyPair()`

> `public static` loadSignatureKeyPair(`string $filePath`): [`SignatureKeyPair`](SignatureKeyPair.md)

Load an `SignatureKeyPair` from a file.

### `save()`

> `public static` save(`Key|KeyPair $key`, `string $filename = ''`)

Save a key to a file.
