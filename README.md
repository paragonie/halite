# Halite

[![Build Status](https://travis-ci.org/paragonie/halite.svg?branch=master)](https://travis-ci.org/paragonie/halite)

Halite is a high-level cryptography interface that relies on [libsodium](https://pecl.php.net/package/libsodium)
for all of its underlying cryptography operations.

Halite was created by [Paragon Initiative Enterprises](https://paragonie.com) as
a result of our continued efforts to improve the ecosystem and make [cryptography in PHP](https://paragonie.com/blog/2015/09/state-cryptography-in-php)
safer and easier to implement.

It's released under the GPLv3 license. [Commercial licenses are available](https://paragonie.com/contact) from
Paragon Initiative Enterprises if you wish to implement Halite in an application
without making your source code available under a GPL-compatible license.

## Using Halite in Your Applications

1. [Install Libsodium and the PHP Extension](https://paragonie.com/book/pecl-libsodium/read/00-intro.md#installing-libsodium)
2. `composer require paragonie/halite`

## Halite Features

These are the high-level APIs we expose to the developer. We will attempt to
document these features in detail in the `doc/` directory.

### Generating Keys and Keypairs

To generate an cryptography key, simply pass the appropriate flags to `Key::generate`

```php
<?php
use \ParagonIE\Halite\Key;

/**
 * Symmetric-key cryptography:
 */
    // For symmetric-key encryption:
    $encryption_key = Key::generate(Key::SECRET_KEY | Key::ENCRYPTION);

    // For symmetric-key authentication:
    $message_auth_key = Key::generate(Key::SECRET_KEY | Key::AUTHENTICATION);

/**
 * Asymmetric-key cryptography -- Key::generate() returns an array:
 */
    // For asymmetric-key encryption:
    list($enc_secret, $enc_public) = Key::generate(Key::ASYMMETRIC | Key::ENCRYPTION);

    // For asymmetric-key authentication (digital signatures):
    list($sign_secret, $sign_public) = Key::generate(Key::ASYMMETRIC | Key::AUTHENTICATION);

/**
 * Short-hand methods; the constants are named after the features they are
 * analogous to in libsodium proper:
 */
$encryption_key = Key::generate(Key::CRYPTO_SECRETBOX);
$message_auth_key = Key::generate(Key::CRYPTO_AUTH);
list($enc_secret, $enc_public) = Key::generate(Key::CRYPTO_BOX);
list($sign_secret, $sign_public) = Key::generate(Key::CRYPTO_SIGN);
```

`Key::generate()` accepts a second optional parameter, a reference to a
variable, which it will overwrite with the secret key.

```php
$my_secret_key = '';
$keypair = Key::generate(Key::CRYPTO_BOX, $my_secret_key);

// If you were to print \Sodium\bin2hex($my_secret_key)), you would get a 64
// character hexadecimal string with your private key.

// If you wish to store the secret key for long-term use, you can simply do
// this:
\file_put_contents('/path/to/secretkey', $my_secret_key);
\Sodium\memzero($my_secret_key);

// And retrieval is simple too:
$string = \file_get_contents('/path/to/secretkey');
$key_object = new Key($string, false, false, true);

// See doc/Key.md for more information
```

### Symmetric-Key String Encryption

Encryption:

```php
<?php
use \ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
/**
 * This will return a hex-encoded string.
 * 
 * $plaintext is your message
 * $encryption_key is a Key object (generated above)
 */
$ciphertext = SymmetricCrypto::encrypt($plaintext, $encryption_key);

/**
 * To get raw binary, pass TRUE as the third argument:
 */
$raw_ciphertext = SymmetricCrypto::encrypt($plaintext, $encryption_key, true);
```

Decryption:

```php
/**
 * This expects a hex-encoded string.
 */
$decrypted = SymmetricCrypto::decrypt($ciphertext, $encryption_key);

/**
 * If you're decrypting raw binary, pass TRUE to the third argument:
 */
$raw_decrypt = SymmetricCrypto::decrypt($raw_ciphertext, $encryption_key, true);
```

### Asymmetric-Key String Encryption

```php
use \ParagonIE\Halite\KeyPair;

// Generate a key pair like so:
list ($enc_secret, $enc_public) = \ParagonIE\Halite\KeyPair::generate();
```

#### Anonymous Public-Key Encryption

Encrypt with Public Key:

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$encrypted = AsymmetricCrypto::seal($plaintext, $enc_public);
$raw_encrypt = AsymmetricCrypto::seal($plaintext, $enc_public, true);
```

Decrypt with Secret Key:

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$decrypted = AsymmetricCrypto::unseal($encrypted, $enc_secret);
$raw_decrypt = AsymmetricCrypto::unseal($raw_encrypt, $enc_secret, true);
```
#### Authenticated Public-Key Encryption

Getting the other party's public key:

```php
$recip_public = new \ParagonIE\Halite\Asymmetric\PublicKey(
    $raw_binary_string_here
);
```

Authenticated Public-Key String Encryption:

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$encrypted = AsymmetricCrypto::encrypt($plaintext, $enc_secret, $recip_public);
$raw_encrypt = AsymmetricCrypto::encrypt($plaintext, $enc_secret, $recip_public, true);
```

Authenticated Public-Key String Decryption:

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$decrypted = AsymmetricCrypto::decrypt($plaintext, $enc_public, $recip_secret);
$raw_decrypt = AsymmetricCrypto::decrypt($plaintext, $enc_public, $recip_secret, true);
```

### Secure Password Storage (Hash-then-Encrypt)

#### Creating a password

```php
<?php
use \ParagonIE\Halite\Password;
use \ParagonIE\Halite\Key;

// See above for where $encryption_key is generated
$stored_hash = Password::hash($plaintext_password, $encryption_key);
```

The above snippet will return a long string of hex characters.

#### Validating a password

```php
<?php
use \ParagonIE\Halite\Password;

try {
    if (Password::verify($plaintext_password, $stored_hash, $encryption_key)) {
        // Password matches
    }
} catch (CryptoException\InvalidMessage $ex) {
    // Handle an invalid message here. This usually means tampered cipheretxt.
}
```

### Secure Encrypted Cookies

```php
<?php
use \ParagonIE\Halite\Cookie;

$cookie = new Cookie($encryption_key);

$cookie->store('index', $any_value);
$some_value = $cookie->fetch('other_index');
```

### File Encryption

#### Symmetric-key File Encryption

```php
<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

$encryption_key = \ParagonIE\Halite\Symmetric\SecretKey::generate();

// Encryption
File::encryptFile('originalFile.png', 'encryptedFile.png', $encryption_key);

// Decryption
File::decryptFile('encryptedFile.png', 'decryptedFile.png', $encryption_key);
```

#### Asymmetric-key File Encryption

```php
<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

list($enc_secret, $enc_public) = \ParagonIE\Halite\KeyPair::generate();

// Encryption
File::sealFile('originalFile.png', 'sealedFile.png', $enc_public);

// Decryption
File::unsealFile('sealedFile.png', 'unsealedFile.png', $enc_secret);
```
