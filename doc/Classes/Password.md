# Password (abstract)

**Namespace**: `\ParagonIE\Halite`

A simplified interface for storing encrypted password hashes (hash then encrypt)
for user authentication, powered by our [symmetric-key cryptography](Symmetric/Crypto.md).

## Static Methods

### `hash()`

> `public static` hash(`HiddenString $password`, `EncryptionKey $secret_key`): `HiddenString`

Hash a password (with a randomly generated Argon2 salt), then encrypt the hash
using our [symmetric encryption key](Symmetric/EncryptionKey.md).

### `verify()`

> `public static` verify(`HiddenString $password`, `HiddenString $stored`, `EncryptionKey $secret_key`): `bool`

Decrypt the `$stored` password hash, then verify that it matches the given 
`$password`.
