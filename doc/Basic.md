# Basic Halite Usage

This is the Basic Halite API:

  * Encryption
    * Symmetric
       * `Symmetric\Crypto::encrypt`(`HiddenString`, [`EncryptionKey`](Classes/Symmetric/EncryptionKey.md), `bool?`): `string`
       * `Symmetric\Crypto::decrypt`(`string`, [`EncryptionKey`](Classes/Symmetric/EncryptionKey.md), `bool?`): `HiddenString`
    * Asymmetric
       * Anonymous
         * `Asymmetric\Crypto::seal`(`HiddenString`, [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `string`
         * `Asymmetric\Crypto::unseal`(`string`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md), `bool?`): `HiddenString`
       * Authenticated
         * `Asymmetric\Crypto::encrypt`(`HiddenString`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `string`
         * `Asymmetric\Crypto::decrypt`(`string`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `HiddenString`
  * Authentication
    * Symmetric
       * `Symmetric\Crypto::authenticate`(`string`, [`AuthenticationKey`](Classes/Symmetric/AuthenticationKey.md), `bool?`): `string`
       * `Symmetric\Crypto::verify`(`string`, [`AuthenticationKey`](Classes/Symmetric/AuthenticationKey.md), `string`, `bool?`): `bool`
    * Asymmetric
       * `Asymmetric\Crypto::sign`(`string`, [`SignatureSecretKey`](Classes/Asymmetric/SignatureSecretKey.md), `bool?`): `string`
       * `Asymmetric\Crypto::verify`(`string`, [`SignaturePublicKey`](Classes/Asymmetric/SignaturePublicKey.md), `string`, `bool?`): `bool`

Most of the other [Halite features](Features.md) build on top of these simple APIs.

## Fundamentals

If you're not sure what any of the terms on this page mean, you might be better
served reading our [guide to cryptography terms and concepts for PHP developers](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded).

## Error Handling

Unless stated otherwise, any time Halite encounters invalid data (an attacker
tampered with the ciphertext, you have the wrong decryption key, etc.), Halite
will throw a typed [`Exception`](Classes/Alerts). If you catch one, you should
log the incident and fail closed (i.e. terminate the script gracefully) rather 
than proceeding as if nothing happened.

For authentication functions, Halite will typically just return `false`.

## Encryption

Encryption functions expect your message to be encapsulated in an instance
of the [`HiddenString`](https://github.com/paragonie/hidden-string) class. Decryption functions
will return the decrypted plaintext in a `HiddenString` object.

### Symmetric-Key Encryption

First, you'll need is an encryption key. The easiest way to obtain one is to 
generate it:

```php
use ParagonIE\Halite\KeyFactory;
$enc_key = KeyFactory::generateEncryptionKey();
```

This generates a strong random key. If you'd like to reuse it, you can simply
store it in a file.

```php
KeyFactory::save($enc_key, '/path/to/encryption.key');
```

Later, you can load it like so:

```php
$enc_key = KeyFactory::loadEncryptionKey('/path/to/encryption.key');
```

Or if you want to store it in a string

```php
$key_hex = KeyFactory::export($enc_key)->getString();
```

and get it back later

```php
$enc_key = KeyFactory::importEncryptionKey(new HiddenString($key_hex));
```

--------------------------------------------------------------------------------

**Encryption** should be rather straightforward:

```php
use ParagonIE\HiddenString\HiddenString;

$ciphertext = \ParagonIE\Halite\Symmetric\Crypto::encrypt(
    new HiddenString(
        "Your message here. Any string content will do just fine."
    ),
    $enc_key
);
```

By default, `Crypto::encrypt()` will return a hexadecimal encoded string. If you
want raw binary, simply pass `true` as the third argument (similar to the API
used by PHP's `hash()` function).

The inverse operation, **decryption** is congruent:

```php
$plaintext = \ParagonIE\Halite\Symmetric\Crypto::decrypt(
    $ciphertext,
    $enc_key
);
```

The important thing to keep in mind is that `$enc_key` is not a string, it is an
instance of `\ParagonIE\Halite\Symmetric\EncryptionKey`.

If you're attempting to decrypt a raw binary string rather than a hex-encoded
string, pass `true` to the third argument of `Crypto::decrypt`.

### Authenticated Asymmetric-Key Encryption (Encrypting)

This API facilitates message encryption between to participants in a 
conversation. It requires your secret key and your partner's public key.

Assuming you are Alice, you would generate your keypair like so. (The other
person, Bob, will do the same on his end.)

```php
$alice_keypair = \ParagonIE\Halite\KeyFactory::generateEncryptionKeyPair();
$alice_secret = $alice_keypair->getSecretKey();
$alice_public = $alice_keypair->getPublicKey();
$send_to_bob = sodium_bin2hex($alice_public->getRawKeyMaterial());
```

Alice will then load Bob's public key into the appropriate object like so:

```php
use ParagonIE\HiddenString\HiddenString;

$bob_public = new \ParagonIE\Halite\Asymmetric\EncryptionPublicKey(
    new HiddenString(
        sodium_hex2bin($recv_from_bob)
    )
);
```

--------------------------------------------------------------------------------

**Encrypting** a message from Alice to send to Bob:

```php
$send_to_bob = \ParagonIE\Halite\Asymmetric\Crypto::encrypt(
    new HiddenString(
        "Your message here. Any string content will do just fine."
    ),
    $alice_secret,
    $bob_public
);
```

As with symmetric-key encryption, this defaults to hexadecimal encoded output.
If you desire raw binary, you can pass an optional `true` as the fourth argument
to `Crypto::encrypt()`.

**Decrypting** a message that Alice received from Bob:

```php
$message = \ParagonIE\Halite\Asymmetric\Crypto::decrypt(
    $received_ciphertext,
    $alice_secret,
    $bob_public
);
```

### Anonymous Asymmetric-Key Encryption (Sealing)

A sealing interface is one where you encrypt a message with a public key, such
that only the person possessing the corresponding secret key can decrypt it.

If you wish to seal information, you only need one keypair rather than two:

```php
$seal_keypair = \ParagonIE\Halite\KeyFactory::generateEncryptionKeyPair();
$seal_secret = $seal_keypair->getSecretKey();
$seal_public = $seal_keypair->getPublicKey();
```

You want to only keep `$seal_public` stored outside of the trusted environment.

--------------------------------------------------------------------------------

**Encrypting** an anonymous message:

```php
use ParagonIE\HiddenString\HiddenString;

$sealed = \ParagonIE\Halite\Asymmetric\Crypto::seal(
    new HiddenString(
        "Your message here. Any string content will do just fine."
    ),
    $seal_public
);
```

Once again, this defaults to hexadecimal encoded output. If you desire raw 
binary, you can pass an optional `true` as the fourth argument to 
`Crypto::seal()`.

**Decrypting** an anonymous message:

```php
$opened = \ParagonIE\Halite\Asymmetric\Crypto::unseal(
    $sealed,
    $seal_secret
);
```

## Authentication

### Symmetric-Key Authentication

Symmetric-key authentication is useful if you'd like to authenticate, but not
encrypt, some information that you transfer over a network or share with your
end users.

First, you will need an appropriate key. The easiest way to get one is to simply
generate one randomly then store it for reuse (similar to secret-key encryption
above):

```php
$auth_key = \ParagonIE\Halite\KeyFactory::generateAuthenticationKey();
```

--------------------------------------------------------------------------------

**Authenticating** a message:

```php
// MAC stands for Message Authentication Code
$mac = \ParagonIE\Halite\Symmetric\Crypto::authenticate(
    "Your message here. Any string content will do just fine.",
    $auth_key
);
```

**Verifying** a message, given the message and a message authentication code:

```php
$valid = \ParagonIE\Halite\Symmetric\Crypto::verify(
    "Your message here. Any string content will do just fine.",
    $auth_key,
    $mac
);
if ($valid) {
    // Success!
}
```

By default, `$mac` will be hex-encoded. If you need a raw binary string, pass
`true` as the third (optional) argument to `Crypto::authenticate()`. You will 
also need to pass `true` as the fourth (optional) argument in `Crypto::verify()`.

### Asymmetric-Key Authentication (Digital Signatures)

As with anonymous asymmetric-key encryption, you only need one keypair and you
only give out your public key.

```php
$sign_keypair = \ParagonIE\Halite\KeyFactory::generateSignatureKeyPair();
$sign_secret = $sign_keypair->getSecretKey();
$sign_public = $sign_keypair->getPublicKey();
```

--------------------------------------------------------------------------------

**Signing** a message with a secret key:

```php
$signature = \ParagonIE\Halite\Asymmetric\Crypto::sign(
    "Your message here. Any string content will do just fine.",
    $sign_secret
);
```

**Verifying** the signature of a message with its corresponding public key:

```php
$valid = \ParagonIE\Halite\Asymmetric\Crypto::verify(
    "Your message here. Any string content will do just fine.",
    $sign_public,
    $signature
);
```

The typical rules for hex-encoding apply here as well.
