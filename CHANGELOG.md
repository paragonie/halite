# Changelog

## Version 4.0.0 (2017-09-16)

* Bump minimum PHP version to **7.2.0**, which will be available before the end of 2017
* New methods: `encryptWithAd()` and `decryptWithAd()`, for satisfying true AEAD needs
* Encrypted password hashing through our `Password` class can also accept an optional, 
  additional data parameter
* `HiddenString` objects can now be directly compared
  * `$hiddenString->equals($otherHiddenString)`
* Added Psalm to our Continuous Integration to assure Halite is fully type-safe
* Updated unit tests to be compatible with PHPUnit 6

## Version 3.2.0 (2016-12-08)

* Resolved [#49](https://github.com/paragonie/halite/issues/49), which
  requested making `HiddenString` defend against `serialize()` leaks.
* Fixed an encoding issue which broke legacy passwords. 
  (Discovered in the course of CMS Airship development.)
* The `File` API now supports different encodings for signatures and 
  checksums (more than just hex and binary).

## Version 3.1.1 (2016-10-26)

* Fixed [#44](https://github.com/paragonie/halite/issues/44), which
  caused Halite to be unusable for Symfony users. Thanks, [Usman Zafar](https://github.com/usmanzafar).

## Version 3.1.0 (2016-08-22)

* Added an `export()` method to `KeyFactory`, and congruent `import*()`
  methods. For example:
  * `export($key)` returns a `HiddenString` with a versioned and
     checksummed, hex-encoded string representing the key material.
  * `importEncryptionKey($hiddenString)` expects an `EncryptionKey`
     object or throws a `TypeError`

## Version 3.0.0 (2016-07-30)

* Use [paragonie/constant_time_encoding](https://github.com/paragonie/constant_time_encoding) 
* We now default to URL-safe Base 64 encoding (RFC 4648) 
* API change: Plaintext and password inputs must be a `HiddenString`
  object.
* Dropped support for version 1.
  * We no longer offer or use scrypt anywhere. Everything is Argon2 now.
  * `KeyFactory` no longer accepts a `$legacy` argument.
* Added `TrimmedMerkleTree` to `Structures`.
* Use `is_callable()` instead of `function_exists()` for better
  compatibility with Suhosin.

## Version 2.1.2 (2016-07-11)

* Better docblocks, added unit test to prevent regressions.

## Version 2.1.1 (2016-05-15)

* Prevent an undefined index error when calculating the root of an empty MerkleTree.

## Version 2.1.0 (2016-05-07)

* Key derivation (via `KeyFactory`) can now accept an extra argument to 
  specify the security level of the derived key.
  * Scrypt: `INTERACTIVE` or `SENSITIVE`
  * Argon2i: `INTERACTIVE`, `MODERATE`, or `SENSITIVE`
* `Password` can now accept a security level argument. We recommend
  sticking with `INTERACTIVE` for end users, but if you'd rather make
  administrative accounts cost more to attack, now you can make that
  happen within Halite.
* `MerkleTree` can now accept a personalization string for the hash 
  calculation.
* `MerkleTree` can output a specific hash length (between 16 and 64).
* Both `MerkleTree` and `Node` now lazily calculate the Merkle root 
  rather than calculating it eagerly. This results in less CPU waste.
* Cleaned up the legacy cruft in the `Key` classes. Now they only accept
  a string in their constructor.

## Version 2.0.1 (2016-04-20)

* Fixed conflict with PHP 7 string optimizations that was causing `File::decrypt()` to fail in PHP-FPM.
* Introduced a new method, `Util::safeStrcpy()`, to facilitate safe string duplication without triggering the optimizer.

## Version 2.0.0 (2016-04-04)

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
