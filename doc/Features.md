# Halite Features

In addition to its [core functionality](Basics.md), Halite offers some useful
APIs for solving common problems.

* `Cookie` - Authenticated encryption for your HTTPS cookies
* `File` - Cryptography library for working with files
* `Password` - Secure password storage and password verification API

## Cookie Encryption/Decryption

Unlike the core Halite APIs, the Cookie class is not static. You must create an
instance of `Cookie` and work with it.

```php
$enc_key = \ParagonIE\Halite\Symmetric\EncryptionKey::fromFile('/path/to/key');
$cookie = new \ParagonIE\Halite\Cookie($enc_key);
```

From then on, all you need to do is use the `fetch()` and `store()` APIs.

**Storing** data in an encrypted cookie:

```php
$cookie->store(
    'auth',
    ['s' => $selector, 'v' => $verifier],
    time() + 2592000
);
```

**Fetching** data from an encrypted cookie:

```php
$token = $cookie->fetch('auth');
var_dump($token); // array(2) ...
```

## File Cryptography

Halite's `File` class provides streaming file cryptography features, such as
authenticated encryption and digital signatures. `File` allows developers to
perform secure cryptographic operations on large files with a low memory
footprint.

The `File` API looks like this:

* Filenames
  * `File::encryptFile`(`string`, `string`, [`EncryptionKey`](Classes/Symmetric/EncryptionKey.md))
  * `File::decryptFile`(`string`, `string`, [`EncryptionKey`](Classes/Symmetric/EncryptionKey.md))
  * `File::sealFile`(`string`, `string`, [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md))
  * `File::unsealFile`(`string`, `string`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md))
  * `File::signFile`(`string`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md)): `string`
  * `File::verifyFile`(`string`, [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md)): `bool`
* Resources
  * `File::encryptResource`(`resource`, `resource`, `EncryptionKey`)
  * `File::decryptResource`(`resource`, `resource`, `EncryptionKey`)
  * `File::sealResource`(`resource`, `resource`, [`EncryptionPublicKey`](Classes/Asymmetric/EncryptionPublicKey.md))
  * `File::unsealResource`(`resource`, `resource`, [`EncryptionSecretKey`](Classes/Asymmetric/EncryptionSecretKey.md))

