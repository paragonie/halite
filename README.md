# Halite

[![Build Status](https://travis-ci.org/paragonie/halite.svg?branch=master)](https://travis-ci.org/paragonie/halite)
[![Latest Stable Version](https://poser.pugx.org/paragonie/halite/v/stable)](https://packagist.org/packages/paragonie/halite)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/halite/v/unstable)](https://packagist.org/packages/paragonie/halite)
[![License](https://poser.pugx.org/paragonie/halite/license)](https://packagist.org/packages/paragonie/halite)

Halite is a high-level cryptography interface that relies on [libsodium](https://pecl.php.net/package/libsodium)
for all of its underlying cryptography operations.

Halite was created by [Paragon Initiative Enterprises](https://paragonie.com) as
a result of our continued efforts to improve the ecosystem and make [cryptography in PHP](https://paragonie.com/blog/2015/09/state-cryptography-in-php)
safer and easier to implement.

It's released under the GPLv3 license. [Commercial licenses are available](https://paragonie.com/contact) from
Paragon Initiative Enterprises if you wish to implement Halite in an application
without making your source code available under a GPL-compatible license.

If you are satisfied with the terms of GPLv3 software for backend web applications
but would like to purchase a support contract for your application that uses Halite,
those are also offered by Paragon Initiative Enterprises.

## Installing Halite

Before you can use Halite, you must choose a version that fits the requirements 
of your project. The differences between the requirements for the available 
versions of Halite are briefly highlighted below.

|                                                            | PHP   | libsodium | PECL libsodium |
|------------------------------------------------------------|-------|-----------|----------------|
| Halite 4                                                   | 7.2.0 | 1.0.13    | N/A (standard) |
| [Halite 3](https://github.com/paragonie/halite/tree/v3.x)  | 7.0.0 | 1.0.9     | 1.0.6 / 2.0.4  |
| [Halite 2](https://github.com/paragonie/halite/tree/v2.2)  | 7.0.0 | 1.0.9     | 1.0.6          |

If you need a version of Halite before 4.0, see the documentation relevant to that
particular branch.

## Using Halite in Your Project

Check out the [documentation](doc). The basic Halite API is designed for simplicity:

  * Encryption
    * Symmetric
       * `Symmetric\Crypto::encrypt`([`HiddenString`](doc/Classes/HiddenString.md), [`EncryptionKey`](doc/Classes/Symmetric/EncryptionKey.md)): `string`
       * `Symmetric\Crypto::decrypt`(`string`, [`EncryptionKey`](doc/Classes/Symmetric/EncryptionKey.md)): [`HiddenString`](doc/Classes/HiddenString.md)
    * Asymmetric
       * Anonymous
         * `Asymmetric\Crypto::seal`([`HiddenString`](doc/Classes/HiddenString.md), [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md)): `string`
         * `Asymmetric\Crypto::unseal`(`string`, [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md)): [`HiddenString`](doc/Classes/HiddenString.md)
       * Authenticated
         * `Asymmetric\Crypto::encrypt`([`HiddenString`](doc/Classes/HiddenString.md), [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md)): `string`
         * `Asymmetric\Crypto::decrypt`(`string`, [`EncryptionSecretKey`](doc/Classes/Asymmetric/EncryptionSecretKey.md), [`EncryptionPublicKey`](doc/Classes/Asymmetric/EncryptionPublicKey.md)): [`HiddenString`](doc/Classes/HiddenString.md)
  * Authentication
    * Symmetric
       * `Symmetric\Crypto::authenticate`(`string`, [`AuthenticationKey`](doc/Classes/Symmetric/AuthenticationKey.md)): `string`
       * `Symmetric\Crypto::verify`(`string`, [`AuthenticationKey`](doc/Classes/Symmetric/AuthenticationKey.md), `string`): `bool`
    * Asymmetric
       * `Asymmetric\Crypto::sign`(`string`, [`SignatureSecretKey`](doc/Classes/Asymmetric/SignatureSecretKey.md)): `string`
       * `Asymmetric\Crypto::verify`(`string`, [`SignaturePublicKey`](doc/Classes/Asymmetric/SignaturePublicKey.md), `string`): `bool`

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
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;

$encryptionKey = KeyFactory::loadEncryptionKey('/path/outside/webroot/encryption.key');

$message = new HiddenString('This is a confidential message for your eyes only.');
$ciphertext = Symmetric::encrypt($message, $encryptionKey);

$decrypted = Symmetric::decrypt($ciphertext, $encryptionKey);

var_dump($decrypted === $message); // bool(true)
```

This should produce something similar to:

    MUIDAEpQznohvNlQ-ZRk-ZZ59Mmox75D_FgAIrXY2cUfStoeL-GIeAe0m-uaeURQdPsVmc5XxRw3-2x5ZAsZH_es37qqFuLFjUI-XK9uG0s30YTsorWfpHdbnqzhRuUOI09c-cKrfMQkNBNm0dDDwZazjTC48zWikRHSHXg8NXerVDebzng1aufc_S-osI_zQuLbZDODujEnpbPZhMMcm4-SWuyVXcBPdGZolJyT


### Example: Generating a key from a password

```php
<?php
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;

$passwd = new HiddenString('correct horse battery staple');
// Use random_bytes(16); to generate the salt:
$salt = "\xdd\x7b\x1e\x38\x75\x9f\x72\x86\x0a\xe9\xc8\x58\xf6\x16\x0d\x3b";

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
