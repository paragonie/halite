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

## Halite's API at a Glance

### Cryptography Keys

* `\ParagonIE\Halite\Asymmetric\EncryptionSecretKey`
* `\ParagonIE\Halite\Asymmetric\EncryptionPublicKey`
* `\ParagonIE\Halite\Asymmetric\SignatureSecretKey`
* `\ParagonIE\Halite\Asymmetric\SignaturePublicKey`
* `\ParagonIE\Halite\Symmetric\AuthenticationKey`
* `\ParagonIE\Halite\Symmetric\EncryptionKey`

### String encryption / decryption (symmetric-key)

```php
string \ParagonIE\Halite\Symmetric\Crypto::encrypt(
    string $plaintext,
    EncryptionKey $key,
    boolean $raw_binary
);
string \ParagonIE\Halite\Symmetric\Crypto::decrypt(
    string $ciphertext,
    EncryptionKey $key,
    boolean $raw_binary
);
```

### String encryption / decryption (asymmetric-key)

```php
// If you want both participants to be capable of decryption:
string \ParagonIE\Halite\Asymmetric\Crypto::encrypt(
    string $plaintext,
    EncryptionSecretKey $mySecretKey,
    EncryptionPublicKey $theirPublicKey,
    boolean $raw_binary
);
string \ParagonIE\Halite\Asymmetric\Crypto::decrypt(
    string $plaintext,
    EncryptionSecretKey $mySecretKey,
    EncryptionPublicKey $theirPublicKey,
    boolean $raw_binary
);
// If only the recipient should be capable of decryption:
string \ParagonIE\Halite\Asymmetric\Crypto::seal(
    string $plaintext,
    EncryptionPublicKey $theirPublicKey,
    boolean $raw_binary
);
string \ParagonIE\Halite\Asymmetric\Crypto::unseal(
    string $ciphertext,
    EncryptionSecretKey $mySecretKey,
    boolean $raw_binary
);
```

## Halite Features in Depth

These are the high-level APIs we expose to the developer. We will attempt to
document these features in detail in the `doc/` directory.

### Generating Keys and Key-Pairs

Generating a cryptography key is simple and convenient:

```php
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\EncryptionKeyPair;
use \ParagonIE\Halite\SignatureKeyPair;
use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;

/**
 * Symmetric-key cryptography:
 */
    // For symmetric-key encryption:
    $encryption_key = EncryptionKey::generate();
    
    // For symmetric-key authentication:
    $message_auth_key = AuthenticationKey::generate();

/**
 * Asymmetric-key cryptography:
 */
    // For asymmetric-key encryption:
    $enc_keypair = EncryptionKeyPair::generate();
    $enc_secret = $enc_keypair->getSecretKey();
    $enc_public = $enc_keypair->getPublicKey();

    // For asymmetric-key authentication (digital signatures):
    $sign_keypair = SignatureKeyPair::generate();
    $sign_secret = $sign_keypair->getSecretKey();
    $sign_public = $sign_keypair->getPublicKey();
```

#### Advanced Usage (the old way)

Another way to generate a cryptography key is to pass the appropriate flags to 
`Key::generate`. This will still return one of three types:

* `\ParagonIE\Halite\Asymmetric\PublicKey`
* `\ParagonIE\Halite\Asymmetric\SecretKey`
* `\ParagonIE\Halite\Symmetric\SecretKey` for all symmetric-key crypto

```php
use \ParagonIE\Halite\Key;

/**
 * Symmetric-key cryptography:
 */
    // For symmetric-key encryption:
    $encryption_key = Key::generate(Key::SECRET_KEY | Key::ENCRYPTION);
    
    // For symmetric-key authentication:
    $message_auth_key = Key::generate(Key::SECRET_KEY | Key::SIGNATURE);

/**
 * Asymmetric-key cryptography -- Key::generate() returns an array:
 */
    // For asymmetric-key encryption:
    list($enc_secret, $enc_public) = Key::generate(Key::ASYMMETRIC | Key::ENCRYPTION);

    // For asymmetric-key authentication (digital signatures):
    list($sign_secret, $sign_public) = Key::generate(Key::ASYMMETRIC | Key::SIGNATURE);

/**
 * Short-hand methods; the constants are named after the features they are
 * analogous to in libsodium proper:
 */
$encryption_key = Key::generate(Key::CRYPTO_SECRETBOX);
$message_auth_key = Key::generate(Key::CRYPTO_AUTH);
list($enc_secret, $enc_public) = Key::generate(Key::CRYPTO_BOX);
list($sign_secret, $sign_public) = Key::generate(Key::CRYPTO_SIGN);
```

`Key::generate()` and `KeyPair::generate()` both accept a second optional 
parameter, a reference to a variable, which it will overwrite with the secret
key.

```php
$keypair = KeyPair::generate(Key::CRYPTO_BOX, $my_secret_key);

// If you were to print \Sodium\bin2hex($my_secret_key)), you would get a 64
// character hexadecimal string with your private key.

// If you wish to store the secret key for long-term use, you can simply do
// this:
$keypair->saveToFile('/path/to/secretkey');
\Sodium\memzero($my_secret_key);

// And retrieval is simple too:
$key_object = KeyPair::fromFile('/path/to/secretkey', Key::CRYPTO_BOX);

// See doc/Key.md for more information
```

### Symmetric-Key String Encryption

Encryption:

```php
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
$enc_keypair = \ParagonIE\Halite\KeyPair::generate();
$enc_secret = $enc_keypair->getSecretKey();
$enc_public = $enc_keypair->getPublicKey();
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
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$encrypted = AsymmetricCrypto::encrypt($plaintext, $enc_secret, $recip_public);
$raw_encrypt = AsymmetricCrypto::encrypt($plaintext, $enc_secret, $recip_public, true);
```

Authenticated Public-Key String Decryption:

```php
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$decrypted = AsymmetricCrypto::decrypt($plaintext, $enc_public, $recip_secret);
$raw_decrypt = AsymmetricCrypto::decrypt($plaintext, $enc_public, $recip_secret, true);
```

#### Asymmetric Digital Signatures

Generating a digital signature keypair:

```php
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$sign_keypair = KeyPair::generate(Key::CRYPTO_SIGN);
$sign_secret = $sign_keypair->getSecretKey();
$sign_public = $sign_keypair->getPublicKey();
```

Signing a message:

```php
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

$signature = AsymmetricCrypto::sign($message, $sign_secret);
```

Verifying the signature for a given message:

```php
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;

if (AsymmetricCrypto::verify($message, $sign_public, $signature)) {
    // Signature is good
}
```

### Secure Password Storage (Hash-then-Encrypt)

#### Creating a password

```php
use \ParagonIE\Halite\Password;
use \ParagonIE\Halite\Key;

// See above for where $encryption_key is generated
$stored_hash = Password::hash($plaintext_password, $encryption_key);
```

The above snippet will return a long string of hex characters.

#### Validating a password

```php
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
use \ParagonIE\Halite\Cookie;

$cookie = new Cookie($encryption_key);

$cookie->store('index', $any_value);
$some_value = $cookie->fetch('other_index');
```

### File Encryption

#### File Hashing (Checksum)

Quickly calculate the BLAKE2b hash of a large file while consuming low amounts
of memory.

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

// 128 character hexadecimal hash:
$checksum = File::checksumFile('sourceFile.png');

// 64 character raw binary hash:
$checksum = File::checksumFile('sourceFile.png', true);
```

#### Symmetric-key File Encryption

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

$encryption_key = SymmetricKey::generate(Key::ENCRYPTION);

// Encryption
File::encryptFile('originalFile.png', 'encryptedFile.png', $encryption_key);

// Decryption
File::decryptFile('encryptedFile.png', 'decryptedFile.png', $encryption_key);
```

#### Asymmetric-key File Encryption

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

$enc_keypair = KeyPair::generate(Key::ENCRYPTION);
$enc_secret = $enc_keypair->getSecretKey();
$enc_public = $enc_keypair->getPublicKey();

// Encryption
File::sealFile('originalFile.png', 'sealedFile.png', $enc_public);

// Decryption
File::unsealFile('sealedFile.png', 'unsealedFile.png', $enc_secret);
```

#### Asymmetric-key Digital Signatures for Files

```php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\Alerts\Crypto as CryptoException;

$sign_keypair = KeyPair::generate(Key::CRYPTO_SIGN);
$sign_secret = $sign_keypair->getSecretKey();
$sign_public = $sign_keypair->getPublicKey();

// Authentication
$signature = File::signFile('originalFile.png', $sign_secret);

// Verification
$valid = File::verifyFile('originalFile', $sign_secret, $signature);
```
