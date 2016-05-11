# File

**Namespace**: `\ParagonIE\Halite`

## Methods

### `checksum()`

> `public static` checksum(`$filepath`, [`Key`](Key.md) `$key = null`, `$raw = false`) : `string`

Calculates a BLAKE2b-512 hash of the given file.

* `$filepath` - Path to a file (or an open file handle)
* `$key` (optional, should be an [`AuthenticationKey`](Symmetric/AuthenticationKey.md) or [`SignaturePublicKey`](Asymmetric/SignaturePublicKey.md))
* `$raw` - Set to `TRUE` if you don't want a hexadecimal string returned

### `encrypt()`

> `public static` encrypt(`$input`, `$output`, [`EncryptionKey`](Symmetric/EncryptionKey.md) `$key`): `string`

Encrypt the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string or a resource.

### `decrypt()`

> `public static` decrypt(`$input`, `$output`, [`EncryptionKey`](Symmetric/EncryptionKey.md) `$key`): `string`

Decrypt the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string or a resource.

### `seal()`

> `public static` seal(`$input`, `$output`, [`EncryptionPublicKey`](Asymmetric/EncryptionPublicKey.md) `$key`): `string`

Seals (encrypts with a public key) the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string or a resource.

### `unseal()`

> `public static` unseal(`$input`, `$output`, [`EncryptionSecretKey`](Asymmetric/EncryptionSecretKey.md) `$key`) : `string`

Unseals (decrypts with a secret key) the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string or a resource.

### `sign()`

> `public static` sign(`$input`, [`SignatureSecretKey`](Asymmetric/SignatureSecretKey.md) `$key`, `bool $raw_binary`): `string`

Calculate a digital signature of a file.

`$input` can be a string or a resource.

### `verify()`

> `public static` sign(`$input`, [`SignaturePublicKey`](Asymmetric/SignaturePublicKey.md) `$key`, `string $signature`, `boolean $raw_binary`): `bool`

Verifies a digital signature of a file.

`$input` can be a string or a resource.
