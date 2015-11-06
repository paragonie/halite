# Util (abstract)

**Namespace**: `\ParagonIE\Halite`

## Static Methods

### `hkdfBlake2b()`

> `public static` hkdfBlake2b(`string $ikm`, `int $length`, `string $info = ''`, `string $salt = null`): `int`

This is a variant of HKDF (RFC 5869). Instead of HMAC, it uses a keyed hash
function (BLAKE2b) for key splitting.

### `safeStrlen()`

> `public static` safeStrlen(`string $str`): `int`

Designed to withstand `mbstring.func_overload`, this function will always return
the number of bytes in a string rather than UTF-8 characters.

### `safeSubstr()`

> `public static` safeSubstr(`string $str`, `int $start`, `int $length = null`): `string`

Get a substring of raw binary data (immune to being broken by 
`mbstring.func_overload`).
