# Halite

[![Build Status](https://travis-ci.org/paragonie/halite.svg?branch=master)](https://travis-ci.org/paragonie/halite)
[![Latest Stable Version](https://poser.pugx.org/paragonie/halite/v/stable)](https://packagist.org/packages/paragonie/halite)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/halite/v/unstable)](https://packagist.org/packages/paragonie/halite)
[![License](https://poser.pugx.org/paragonie/halite/license)](https://packagist.org/packages/paragonie/halite)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/halite.svg)](https://packagist.org/packages/paragonie/halite)
[![Coverage Status](https://coveralls.io/repos/github/paragonie/halite/badge.svg?branch=master)](https://coveralls.io/github/paragonie/halite?branch=master)

**Halite** is a high-level cryptography interface that relies on [libsodium](https://pecl.php.net/package/libsodium)
for all of its underlying cryptography operations.

Halite was created by [Paragon Initiative Enterprises](https://paragonie.com) as
a result of our continued efforts to improve the ecosystem and make [cryptography in PHP](https://paragonie.com/blog/2015/09/state-cryptography-in-php)
safer and easier to implement.

> You can read the [**Halite Documentation**](https://github.com/paragonie/halite/tree/master/doc) online.

Halite is released under Mozilla Public License 2.0. [Commercial licenses are available](https://paragonie.com/contact)
from Paragon Initiative Enterprises if you wish to extend Halite without making your
derivative works available under the terms of the MPL.

If you are satisfied with the terms of MPL software for backend web applications
but would like to purchase a support contract for your application that uses Halite,
those are also offered by Paragon Initiative Enterprises.

**Important:** Earlier versions of Halite were available under the GNU Public License
version 3 (GPLv3). Only Halite 4.0.1 and newer are available under the Mozilla Public
License terms.

## Installing Halite

Before you can use Halite, you must choose a version that fits the requirements 
of your project. The differences between the requirements for the available 
versions of Halite are briefly highlighted below.

|                                                             | PHP   | libsodium | PECL libsodium | Support                   |
|-------------------------------------------------------------|-------|-----------|----------------|---------------------------|
| Halite 4.1 and newer                                        | 7.2.0 | 1.0.15    | N/A (standard) | :heavy_check_mark: Active |
| [Halite 4.0](https://github.com/paragonie/halite/tree/v4.0) | 7.2.0 | 1.0.13    | N/A (standard) | :heavy_check_mark: Active |
| [Halite 3](https://github.com/paragonie/halite/tree/v3.x)   | 7.0.0 | 1.0.9     | 1.0.6 / 2.0.4  | :x: Not Supported         |
| [Halite 2](https://github.com/paragonie/halite/tree/v2.2)   | 7.0.0 | 1.0.9     | 1.0.6          | :x: Not Supported         |
| [Halite 1](https://github.com/paragonie/halite/tree/v1.x)   | 5.6.0 | 1.0.6     | 1.0.2          | :x: Not Supported         |

If you need a version of Halite before 4.0, see the documentation relevant to that
particular branch.

**To install Halite, you first need to [install libsodium](https://paragonie.com/book/pecl-libsodium/read/00-intro.md#installing-libsodium).**
You may or may not need the PHP extension. For most people, this means running...

    sudo apt-get install php7.2-sodium

...or an equivalent command for your operating system and PHP version.

If you're stuck, [this step-by-step guide contributed by @aolko](doc/Install-Guides/Ubuntu.md) may be helpful.

Once you have the prerequisites installed, install Halite through [Composer](https://getcomposer.org/doc/00-intro.md):

    composer require paragonie/halite:^4

### Commercial Support for Older Halite Versions

Free (gratis) support for Halite only extends to the most recent major version (currently 4).

If your company requires support for an older version of Halite,
[contact Paragon Initiative Enterprises](https://paragonie.com/contact) to inquire about
commercial support options.

If you need an easy way to migrate from older versions of Halite, check out [halite-legacy](https://github.com/paragonie/halite-legacy).

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
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\HiddenString\HiddenString;

$encryptionKey = KeyFactory::loadEncryptionKey('/path/outside/webroot/encryption.key');

$message = new HiddenString('This is a confidential message for your eyes only.');
$ciphertext = Symmetric::encrypt($message, $encryptionKey);

$decrypted = Symmetric::decrypt($ciphertext, $encryptionKey);

var_dump($decrypted->getString() === $message->getString()); // bool(true)
```

This should produce something similar to:

    MUIDAEpQznohvNlQ-ZRk-ZZ59Mmox75D_FgAIrXY2cUfStoeL-GIeAe0m-uaeURQdPsVmc5XxRw3-2x5ZAsZH_es37qqFuLFjUI-XK9uG0s30YTsorWfpHdbnqzhRuUOI09c-cKrfMQkNBNm0dDDwZazjTC48zWikRHSHXg8NXerVDebzng1aufc_S-osI_zQuLbZDODujEnpbPZhMMcm4-SWuyVXcBPdGZolJyT

#### Cryptographic Keys in Halite

> **Important**: Halite works with `Key` objects, not strings.

If you attempt to `echo` a key object, you will get an empty string
rather than its contents. If you attempt to `var_dump()` a key object,
you will just get some facts about the type of key it is.
 
You must invoke `$obj->getRawKeyMaterial()` explicitly if you want
to inspect a key's raw binary contents. This is not recommended for
most use cases.

### Example: Generating a key from a password

```php
<?php
use ParagonIE\Halite\KeyFactory;
use ParagonIE\HiddenString\HiddenString;

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

## Common Support Issues

### Uncaught SodiumException: Cannot Wipe Memory

> PHP Fatal error: Uncaught SodiumException: This is not implemented, as it is not possible to securely wipe memory from PHP

The solution to this is to make sure libsodium is installed/enabled. See above in this
README for more information. 

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).
