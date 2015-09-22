# Halite

[![Build Status](https://travis-ci.org/paragonie/halite.svg?branch=master)](https://travis-ci.org/paragonie/halite)

Halite is a high-level cryptography interface that relies on [libsodium](https://pecl.php.net/package/libsodium)
for all of its underlying cryptography operations.

Halite was created by [Paragon Initiative Enterprises](https://paragonie.com) as
a result of our continued efforts to improve the ecosystem and make [cryptography in PHP](https://paragonie.com/blog/2015/09/state-cryptography-in-php)
safer and easier to implement.

It's released under the GPLv3 license. Commercial licenses are available from
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
use \ParagonIE\Halite\Primitive\Key;

// For symmetric-key encryption:
$encryption_key = Key::generate(Key::CRYPTO_SECRET_KEY | Key::ENCRYPTION);

// For symmetric-key authentication:
$message_auth_key = Key::generate(Key::CRYPTO_SECRET_KEY | Key::AUTHENTICATION);

// For asymmetric-key encryption:
list($enc_secret, $enc_public) = Key::generate(Key::ASYMMETRIC | Key::ENCRYPTION);

// For asymmetric-key authentication (digital signatures):
list($sign_secret, $sign_public) = Key::generate(Key::ASYMMETRIC | Key::AUTHENTICATION);
```

To store an encryption key for long-term use, just do the following:

```php
<?php

$stored_key = \Sodium\bin2hex(
    $encryption_key->get()
);
```

### Secure Password Storage (Hash-then-Encrypt)

#### Creating a password

```php
<?php
use \ParagonIE\Halite\Password;
use \ParagonIE\Halite\Primitive\Key;

// See above for where $encryption_key is generated
$stored_hash = Password::hash($plaintext_password, $encryption_key);
```

The above snippet will return a long string of hex characters.

#### Validating a password

```php
<?php
use \ParagonIE\Halite\Password;
use \ParagonIE\Halite\Primitive\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoAlert;

try {
    if (Password::verify($plaintext_password, $stored_hash, $encryption_key)) {
        // Password matches
    }
} catch (CryptoAlert\InvalidMessage $ex) {
    // Handle an invalid message here. This usually means tampered cipheretxt.
}
```

### Secure Encrypted Cookies

```php
<?php
use \ParagonIE\Halite\Cookie;
use \ParagonIE\Halite\Primitive\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoAlert;

$cookie = new Cookie($encryption_key);

$cookie->store('index', $any_value);
$some_value = $cookie->fetch('other_index');
```

### Symmetric-key File Encryption

```php
<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Primitive\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoAlert;

// Encryption
File::encryptFile('originalFile.png', 'encryptedFile.png', $encryption_key);

// Decryption
File::decryptFile('encryptedFile.png', 'decryptedFile.png', $encryption_key);
```

### Asymmetric-key File Encryption

```php
<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Primitive\Key;
use \ParagonIE\Halite\Alerts\Crypto as CryptoAlert;

// Encryption
File::sealFile('originalFile.png', 'sealedFile.png', $enc_public);

// Decryption
File::unsealFile('sealedFile.png', 'unsealedFile.png', $enc_secret);
```
