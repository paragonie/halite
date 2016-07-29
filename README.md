# Halite

[![Build Status](https://travis-ci.org/paragonie/halite.svg?branch=stable)](https://travis-ci.org/paragonie/halite)
[![Latest Stable Version](https://poser.pugx.org/paragonie/halite/v/stable)](https://packagist.org/packages/paragonie/halite)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/halite/v/unstable)](https://packagist.org/packages/paragonie/halite)
[![License](https://poser.pugx.org/paragonie/halite/license)](https://packagist.org/packages/paragonie/halite)

> **Note**: This is the version 1 branch. Please upgrade to a newer version as soon as possible.

Halite is a high-level cryptography interface that relies on [libsodium](https://pecl.php.net/package/libsodium)
for all of its underlying cryptography operations.

Halite was created by [Paragon Initiative Enterprises](https://paragonie.com) as
a result of our continued efforts to improve the ecosystem and make [cryptography in PHP](https://paragonie.com/blog/2015/09/state-cryptography-in-php)
safer and easier to implement.

It's released under the GPLv3 license. [Commercial licenses are available](https://paragonie.com/contact) from
Paragon Initiative Enterprises if you wish to implement Halite in an application
without making your source code available under a GPL-compatible license.

## Using Halite in Your Applications

### Step 1: Installing libsodium

Before you can use Halite, you must choose a version that fits the requirements 
of your project. The differences between the requirements for the available 
versions of Halite are briefly highlighted below.

|           | PHP   | libsodium | PECL libsodium |
|-----------|-------|-----------|----------------|
| Halite 2+ | 7.0.0 | 1.0.9     | 1.0.6          |
| Halite 1  | 5.6.0 | 1.0.6     | 1.0.2          |

If you plan to use Halite 1, or your distribution has the necessary version already,
then you should be able to
[install a precompiled libsodium](https://paragonie.com/book/pecl-libsodium/read/00-intro.md#installing-libsodium)
package.

### Step 2: Installing the PECL libsodium extension

**Important Note**: It is important that this step is repeated every time that a
different version of libsodium is installed. The resulting PECL libsodium extension
is version dependent of the currently installed libsodium.

Installation instructions for the PECL libsodium extension can be found in the
[PECL libsodium book](https://paragonie.com/book/pecl-libsodium/read/00-intro.md#installing-extension)
on the Paragon Initiative Enterprises website.

### Step 3: Use Composer to install Halite

The last step required to use Halite is to install it using Composer.

For the latest version of Halite:

    composer require paragonie/halite

Or for older versions of Halite, specify the version number:

    composer require paragonie/halite:^v1

## Using Halite in Your Project

Check out the [documentation](doc). The basic Halite API is designed for simplicity:

  * Encryption
    * Symmetric
       * `Symmetric\Crypto::encrypt`(`string`, [`EncryptionKey`](doc/Classes/Symmetric/EncryptionKey.md), `bool?`): `string`
       * `Symmetric\Crypto::decrypt`(`string`, [`EncryptionKey`](doc/Classes/Symmetric/EncryptionKey.md), `bool?`): `string`
    * Asymmetric
       * Anonymous
         * `Asymmetric\Crypto::seal`(`string`, [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `string`
         * `Asymmetric\Crypto::unseal`(`string`, [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md), `bool?`): `string`
       * Authenticated
         * `Asymmetric\Crypto::encrypt`(`string`, [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `string`
         * `Asymmetric\Crypto::decrypt`(`string`, [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md), `bool?`): `string`
  * Authentication
    * Symmetric
       * `Symmetric\Crypto::authenticate`(`string`, [`AuthenticationKey`](doc/Classes/Symmetric/AuthenticationKey.md), `bool?`): `string`
       * `Symmetric\Crypto::verify`(`string`, [`AuthenticationKey`](doc/Classes/Symmetric/AuthenticationKey.md), `string`, `bool?`): `bool`
    * Asymmetric
       * `Asymmetric\Crypto::sign`(`string`, [`SignatureSecretKey`](doc/Classes/Asymmetric/SignatureSecretKey.md), `bool?`): `string`
       * `Asymmetric\Crypto::verify`(`string`, [`SignaturePublicKey`](doc/Classes/Asymmetric/SignaturePublicKey.md), `string`, `bool?`): `bool`

### Example: Encrypting and Decrypting a message

First, generate and persist a key exactly once:

```php
<?php
use ParagonIE\Halite\KeyFactory;

$encKey = KeyFactory::generateEncryptionKey();
KeyFactory::save($encKey, '/path/outside/webroot/encryption.key');
```

And then you can encrypt/decrypt messages like so:

```php
<?php
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;

$encryptionKey = KeyFactory::loadEncryptionKey('/path/outside/webroot/encryption.key');

$message = 'This is a confidential message for your eyes only.';
$ciphertext = Symmetric::encrypt($message, $encryptionKey);

$decrypted = Symmetric::decrypt($ciphertext, $encryptionKey);

var_dump($decrypted === $message); // bool(true)
```

This should produce something similar to:

    314202017d893cb20eeab4ef51f6861d55a60797c6de0453f11e464ce210091b914b1c40470869d3d390986eeebe2d34e393efe986fc52de7464f30d8d38df5c6b629c019c454a2eec03ca618f9e2ba34f20c81614d63988f0f845911cafbeee7e79893e1f7c33e298da3b3474ac3ea9181298a2ce7e468914c329b35f50ac32b01136dc87e7f7881d31909227273817ac01c3b8f19dc6db881ad962d5b3e4c95d61494747028114f15a2e718c19

### Example: Generating a key from a password

```php
<?php
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;

$passwd = 'correct horse battery staple';
// Use random_bytes(32); to generate the salt:
$salt = "\xdd\x7b\x1e\x38\x75\x9f\x72\x86\x0a\xe9\xc8\x58\xf6\x16\x0d\x3b\xdd\x7b\x1e\x38\x75\x9f\x72\x86\x0a\xe9\xc8\x58\xf6\x16\x0d\x3b";

$encryptionKey = KeyFactory::deriveEncryptionKey($passwd, $salt);
```

A key derived from a password can be used in place of one randomly generated.

### Example: Encrypting a large file on a system with low memory

Halite includes a file cryptography class that utilizes a streaming API to
allow large files (e.g. gigabytes) be encrypted on a system with very little
available memory (i.e. less than 8 MB).

```php
<?php
use ParagonIE\Halite\File;
use ParagonIE\Halite\KeyFactory;

$encryptionKey = KeyFactory::loadEncryptionKey('/path/outside/webroot/encryption.key');

File::encrypt('input.txt', 'output.txt', $encryptionKey);
```
