# Key

**Namespace**: `\ParagonIE\Halite`

## Constants

Flags:

```php
    const SECRET_KEY       =   1;
    const PUBLIC_KEY       =   2;
    const ENCRYPTION       =   4;
    const SIGNATURE        =   8;
    const ASYMMETRIC       =  16;
```

Alias Flags:

```php
    const AUTHENTICATION  =   8;
```

Shortcut flags:

```php
    const CRYPTO_SECRETBOX =  5;
    const CRYPTO_AUTH      =  9;
    const CRYPTO_BOX       = 20;
    const CRYPTO_SIGN      = 24;
```

## Methods

### Constructor

**Warning**: You should almost never use `Key` directly. Instead, use one of the child classes.

Arguments:

 * `$keyMaterial` - `HiddenString` containing raw binary data (the cryptographic key)

Example:

```php
// For Symmetric::encrypt()
$enc_secret = new EncryptionKey(
     new HiddenString(str_repeat('A', 32))
);

// For Symmetric::authenticate()
$auth_secret = new AuthenticationKey(
     new HiddenString(str_repeat('A', 32))
);
```

### `getRawKeyMaterial()`

> `public` getRawKeyMaterial()

Simply returns the raw binary key data.

### `isAsymmetricKey()`

>`public` isAsymmetricKey()

Returns true if this is a key meant for asymmetric cryptography.

### `isEncryptionKey()`

> `public` isEncryptionKey()

Returns true if this is a key meant for encryption.

### `isPublicKey()`

> `public` isPublicKey()

Returns true if this is the public key for a given key-pair.

### `isSecretKey()`

> `public` isSecretKey()

Returns true if:

* Symmetric crypto: Always
* Asymmetric crypto: This is the secret key for a given key-pair.

### `isSigningKey()`

> `public` isSigningKey()

Returns true if this is a key meant for authentication
