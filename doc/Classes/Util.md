# Util (abstract)

**Namespace**: `\ParagonIE\Halite`

## Static Methods

### `hash()`

> `public static` hash(`string $input`, `int $length = 32`): `string`

User-friendly wrapper for `sodium_crypto_generichash`.

Returns a hexadecimal-encoded hash of an input, for any length.

### `keyed_hash()`

> `public static` hash(`string $input`, `string $key`, `int $length = 32`): `string`

User-friendly wrapper for `sodium_crypto_generichash`.

Returns a hexadecimal-encoded keyed hash of an input, for any length.

### `raw_hash()`

> `public static` rawhash(`string $input`, `int $length = 32`): `string`

User-friendly wrapper for `sodium_crypto_generichash`.

Returns a raw binary hash of an input, for any length.

### `raw_keyed_hash()`

> `public static` hash(`string $input`, `string $key`, `int $length = 32`): `string`

User-friendly wrapper for `sodium_crypto_generichash`.

Returns a raw binary keyed hash of an input, for any length.

### `hkdfBlake2b()`

> `public static` hkdfBlake2b(`string $ikm`, `int $length`, `string $info = ''`, `string $salt = null`): `int`

This is a variant of HKDF-HMAC (RFC 5869). Instead of HMAC, it uses a keyed hash
function (BLAKE2b) for key splitting.

### `safeStrcpy()`

> `public static` safeStrcpy(`string $str`): `string`

Returns a copy of a string without triggering PHP's optimizations. The
string returned by this method can safely be used with `sodium_memzero()`
without corrupting other copies of the same string.

### `splitKeys()`

Splits a single key into two distinct keys (one for encryption, one for authentication).

Since Halite v5, the HKDF salt parameter is not used. Instead, this randomness is appended
to the HKDF info parameter, in order to meet the [standard security definition for HKDF](https://eprint.iacr.org/2010/264).

Additionally, this allows us to reuse the PRK (the value affected by the HKDF salt) value
for both derived keys, which results in a nice performance gain.

### `xorStrings()`

> `public static` xorStrings(`string $left`, `string $right`): `string`

Calculate A xor B, given two binary strings of the same length.

Uses pack() and unpack() to avoid cache-timing leaks caused by chr().
