# \ParagonIE\Halite\Cookie

Encrypted cookie storage, powered by our [symmetric-key cryptography](Symmetric/Crypto.md).

## Properties

### protected `$key`

Stores the encryption key for this instance of `Cookie`.

## Methods

### Constructor

Arguments:

* [`EncryptionKey $key`](Symmetric/EncryptionKey.md) - The key used for symmetric-key encryption

### `public` fetch(`string $name`)

Fetch the data stored in an encrypted cookie.

### `public` store(`string $name`, `mixed $value`, `int $expire = 0`, `string $path = '/'`, `string $domain = null`, `boolean $secure = true`, `boolean $httponly = true`)

Encrypt then store a cookie.