# Changelog

## Not yet Released - Version 2.0.0

* Halite now requires:
  * PHP 7.0+
  * libsodium 1.0.9+
  * libsodium-php 1.0.3+
  * (You can use `Halite::isLibsodiumSetupCorrectly()` to verify the
    latter two)
* Strictly typed everywhere
* You can no longer pass a well-configured but generic `Key` object to
  most methods; you must pass the appropriate child class (i.e.
  `Symmetric\Crypto::encrypt()` expects an instance of 
  `Symmetric\Crypto\EncryptionKey`.
* Updated password hashing and key derivation to use Argon2i
* `File` now uses a keyed BLAKE2b hash instead of HMAC-SHA256.
* `Key->get()` was renamed to `Key->getRawKeyMaterial()`
* `Password` now has a `needsRehash()` method which will return `true`
  if you're using an obsolete encryption and/or hashing method.
* `Util` now has several new methods for generating BLAKE2b hashes:
  * `hash()`
  * `keyed_hash()`
  * `raw_hash()`
  * `raw_keyed_hash()`
* Removed most of the interfaces in `Contract`