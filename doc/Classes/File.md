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

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

### `decrypt()`

> `public static` decrypt(`$input`, `$output`, [`EncryptionKey`](Symmetric/EncryptionKey.md) `$key`): `string`

Decrypt the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

### `asymmetricDecrypt()`

> `public static` asymmetricDecrypt(`$input`, `$output`, [`EncryptionSecretKey`](Asymmetric/EncryptionSecretKey.md) `$recipientSK`, [`EncryptionPublicKey`](Asymmetric/EncryptionPublicKey.md) `$senderPK`, `string $aad = null`): `int`

Decrypt the contents of `$input` (either a string containing the path to a file, or an open file
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

The difference between `asymmetricDecrypt()` and `deseal()` is that `asymmetricDecrypt()` authenticates the sender, 
while `unseal()` does not. (You can think of `unseal()` as anonymous public-key decryption.)

### `asymmetricEncrypt()`

> `public static` asymmetricEncrypt(`$input`, `$output`, [`EncryptionPublicKey`](Asymmetric/EncryptionPublicKey.md) `$recipientPK`, [`EncryptionSecretKey`](Asymmetric/EncryptionSecretKey.md) `$senderSK`, `string $aad = null`): `int`

Encrypt the contents of `$input` (either a string containing the path to a file, or an open file
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

The difference between `asymmetricEncrypt()` and `seal()` is that `asymmetricEncrypt()` authenticates the sender, while
`seal()` does not. (You can think of `seal()` as anonymous public-key encryption.)

### `seal()`

> `public static` seal(`$input`, `$output`, [`EncryptionPublicKey`](Asymmetric/EncryptionPublicKey.md) `$key`): `string`

Seals (encrypts with a public key) the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

### `unseal()`

> `public static` unseal(`$input`, `$output`, [`EncryptionSecretKey`](Asymmetric/EncryptionSecretKey.md) `$key`) : `string`

Unseals (decrypts with a secret key) the contents of `$input` (either a string containing the path to a file, or an open file 
handle), and store it in the file (handle?) at `$output`.

Both `$input` and `$output` can be a string, a resource, or an object whose class implements `StreamInterface`.
In the object case, `$input` must be an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md) and `$output` must
be an instance of [`MutableFile`](Stream/MutableFile.md).

### `sign()`

> `public static` sign(`$input`, [`SignatureSecretKey`](Asymmetric/SignatureSecretKey.md) `$key`, `bool $raw_binary`): `string`

Calculate a digital signature of a file.

`$input` can be a string or a resource, or an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md).

### `verify()`

> `public static` verify(`$input`, [`SignaturePublicKey`](Asymmetric/SignaturePublicKey.md) `$key`, `string $signature`, `boolean $raw_binary`): `bool`

Verifies a digital signature of a file.

`$input` can be a string or a resource, or an instance of [`ReadOnlyFile`](Stream/ReadOnlyFile.md).
