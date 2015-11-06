# File

**Namespace**: `\ParagonIE\Halite`

## Methods

### `checksum()`

> `public static` checksum(`$filepath`, [`AuthenticationKey`](Symmetric/AuthenticationKey.md) `$key = null`, `$raw = false`) : `string`

Calculates a BLAKE2b-512 hash of the given file.

* `$filepath` - Path to a file (or an open file handle)
* `$key` (optional)
* `$raw` - Set to `TRUE` if you don't want a hexadecimal string returned

### `encrypt()`

> `public static` encrypt(`$input`, `$output`, [`EncryptionKey`](Symmetric/EncryptionKey.md) `$key`) : `string`



### `decrypt()`

> `public static` decrypt(`$input`, `$output`, [`EncryptionKey`](Symmetric/EncryptionKey.md) `$key`) : `string`




### `seal()`

> `public static` seal(`$input`, `$output`, [`EncryptionPublicKey`](Asymmetric/EncryptionPublicKey.md) `$key`) : `string`



### `unseal()`

> `public static` unseal(`$input`, `$output`, [`EncryptionSecretKey`](Asymmetric/EncryptionSecretKey.md) `$key`) : `string`



### `sign()`

> `public static` sign(`$input`, [`SignatureSecretKey`](Asymmetric/SignatureSecretKey.md) `$key`, `boolean $raw_binary`) : `string`



### `verify()`

> `public static` sign(`$input`, [`SignaturePublicKey`](Asymmetric/SignaturePublicKey.md) `$key`, `string $signature`, `boolean $raw_binary`) : `boolean`