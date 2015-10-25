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

