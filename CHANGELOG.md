# Changelog

## Version 5.1.4 (2025-09-18)

* Add PHPStan analysis, level 5 by @spaze in https://github.com/paragonie/halite/pull/195
* Replace all `http://` links with the `https://` URL they redirect to by @GrahamCampbell in https://github.com/paragonie/halite/pull/196
* Use Psalm 6 by @spaze in https://github.com/paragonie/halite/pull/198
* Remove access modifier `final` from private methods by @junaidbinfarooq in https://github.com/paragonie/halite/pull/204
* Ignore tests, workflows and .MD docs with "export-ignore" on .gitattr… by @erikn69 in https://github.com/paragonie/halite/pull/205
* Expand test coverage by @paragonie-security in https://github.com/paragonie/halite/pull/206
* Fixed the broken test coverage badge (https://github.com/paragonie/halite/pull/207 and https://github.com/paragonie/halite/pull/208)

## Version 5.1.3 (2025-01-23)

* Merged [#184](https://github.com/paragonie/halite/pull/194), which fixes PHP 8.4 deprecations with nullable types.

## Version 5.1.2 (2024-05-08)

* Use `#[SensitiveParameter]` annotation on some inputs
  * This is defense in depth; we already wrapped most in `HiddenString`
* Updated dependencies

## Version 5.1.1 (2024-04-19)

* Support both sodium_compat v1 and v2. 
  [Learn more here](https://paragonie.com/blog/2024/04/release-sodium-compat-v2-and-future-our-polyfill-libraries).

## Version 5.1.0 (2022-05-23)

* Dropped PHP 8.0 support, increased minimum PHP version to 8.1.
  * This is due to the significant performance difference between ext/sodium
    and sodium_compat, and the functions we use in 5.x aren't available until
    PHP 8.1. See [#178](https://github.com/paragonie/halite/issues/178).
* The 5.0.x branch will continue to *function* on PHP 8.0 but performance is
  not guaranteed.

## Version 5.0.0 (2022-01-19)

* Increased minimum PHP version to 8.0.
* **Security:** Asymmetric encryption now uses HKDF-BLAKE2b to extract a 256-bit uniformly random bit string for the
  encryption key, rather than using the raw X25519 output directly as an encryption key. This is important because 
  Elliptic Curve Diffie-Hellman results in a random group element, but that isn't necessarily a uniformly random bit
  string.
  * Because Halite v4 and earlier did not perform this step, it's superficially susceptible to
    [Cheon's attack](https://crypto.stackexchange.com/a/67609). This reduces the effective security
    from 125 bits (Pollard's rho) to 123 bits, but neither is a practical concern today.
* **Security:** Halite v5 uses the [PAE](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition)
  strategy from PASETO to prevent canonicalization attacks.
* **Security:** Halite v5 appends the random salt to HKDF's `info` parameter instead of
  the `salt` parameter. This allows us to meet the KDF Security Definition (which is
  stronger than a mere Pseudo-Random Function).
* Encryption now uses XChaCha20 instead of XSalsa20.
* The `File` class no longer supports the `resource` type. To migrate code, wrap your 
  `resource` arguments in a `ReadOnlyFile` or `MutableFile` object.
* Added `File::asymmetricEncrypt()` and `File::asymmetricDecrypt()`.

## Version 4.8.0 (2021-04-18)

* Merged [#158](https://github.com/paragonie/halite/pull/158), which removes
  the `final` access modifier from private methods and guarantees PHP 8 support.
* Migrated tests off of Travis CI, onto Github Actions instead.

## Version 4.7.1 (2020-12-06)

* Allow v2 of `paragonie/hidden-string` to be installed.

## Version 4.7.0 (2020-12-03)

* Merged [#154](https://github.com/paragonie/halite/pull/154), which supports
  the SameSite cookie arguments on PHP 7.3+.
* Create a wrapper for `sodium_memzero()` to support sodium_compat.
* Added support for PHP 8.
* [#146](https://github.com/paragonie/halite/pull/146),
  [#155](https://github.com/paragonie/halite/pull/155),
  [#156](https://github.com/paragonie/halite/pull/156) --
  Various documentation improvements.

## Version 4.6.0 (2019-09-12)

* Merged [#138](https://github.com/paragonie/halite/pull/138), which adds
  remote stream support to `ReadOnlyFile`.
* Merged [#140](https://github.com/paragonie/halite/pull/140), which saves
  some overhead on hash recalculation.
* Merged [#136](https://github.com/paragonie/halite/pull/136) and 
  [#137](https://github.com/paragonie/halite/pull/137), which updated the
  sodium stub files. These aren't strictly necessary anymore; with the
  adoption of libsodium in PHP 7.2 and sodium_compat, most IDEs autocomplete
  correctly. But fixing nits is always appreciated.
* Update minimum sodium_compat to v1.11.0.

## Version 4.5.4 (2019-06-05)

* Merged [#132](https://github.com/paragonie/halite/pull/132), which ensures
  all Halite exceptions implement `Throwable`.
* Merged [#133](https://github.com/paragonie/halite/pull/133), which updates
  the documentation for the `File` API.
  Thanks [@elliot-sawyer](https://github.com/elliot-sawyer). 
* Merged [#134](https://github.com/paragonie/halite/pull/134), which allows
  `MutableFile` to be used on resources opened in `wb` mode.
  Thanks [@christiaanbaartse](https://github.com/christiaanbaartse).
* Other minor documentation improvements.

## Version 4.5.3 (2019-03-11)

* Fixed some minor nuisances with Psalm and PHPUnit.
* Added reference to Halite-Legacy to the README.
* Updated docblocks.

## Version 4.5.2 (2019-02-11)

* Fixed [#116](https://github.com/paragonie/halite/issues/116). If the output file
  doesn't exist, it will be created. If it cannot be created, an exception will
  still be thrown.

## Version 4.5.1 (2019-01-08)

* Use `class_alias()` for `ParagonIE\Halite\HiddenString` to the outsourced library.
  This is **deprecated** and will be removed in version 5.

## Version 4.5.0 (2019-01-03)

* Updated Psalm version from `^0|^1` to `^1|^2`.
* Moved `HiddenString` to a standalone library: https://travis-ci.org/paragonie/hidden-string

## Version 4.4.2 (2018-03-27)

* Updated Psalm version from `^0|^1` to `^1`.
* Type-safety and documentation fixes.
* Miscellaneous boyscouting. No bugs were found since 4.4.1.

## Version 4.4.1 (2018-02-27)

* Fixed [#97](https://github.com/paragonie/halite/issues/97), set the minimum chunk size to 1.

## Version 4.4.0 (2018-02-04)

* Fixed [#90](https://github.com/paragonie/halite/issues/90):
  * Introduced [`WeakReadOnlyFile`](https://github.com/paragonie/halite/blob/master/doc/Classes/Stream/WeakReadOnlyFile.md),
    an alternative to [`ReadOnlyFile`](https://github.com/paragonie/halite/blob/master/doc/Classes/Stream/ReadOnlyFile.md)
    that allows file modes other than `rb`. The TOCTOU security guarantees are therefore
    slightly weaker with this class (hence the "Weak" part of the name).
  * Updated [`File`](https://github.com/paragonie/halite/blob/master/doc/Classes/File.md)
    to allow stream objects (`ReadOnlyFile` and `MutableFile`) to be passed direclty instead
    of strings (for filenames) and resources (for open file handles).

## Version 4.3.1 (2018-01-30)

* Updated the `Halite::VERSION` constant which was previously still `4.2.0`.
* Documentation and unit testing improvements.

## Version 4.3.0 (2018-01-25)

* You can now quickly turn a `SignatureKeyPair` object into a birationally
  equivalent EncryptionKeyPair object by invoking the `getEncryptionKeyPair()`
  method.
* We now have 100% unit test coverage, in addition to our static analysis.

## Version 4.2.0 (2018-01-15)

* Implemented `Asymmetric::signAndEncrypt()` and `Asymmetric::verifyAndDecrypt()`,
  which facilitates the GPG use-case of signed-then-encrypted messages between
  two parties' Ed25519 keypairs. Encryption is facilitated using birationally
  equivalent X25519 keys.
* Removed our in-house implementations of binary-safe `substr` and `strlen` in
  favor of using the ones in the constant-time encoding library.

## Version 4.1.0 (2018-01-05)

Added support for libsodium 1.0.15, which was previously broken in 4.0.x.

Passwords should be autoamtically migrated, but if keys were being generated via
`KeyFactory::derive______Key()` (fill in the blank), you'll need to change your
usage of this API to get the same key as previously. Namely, you'll need to pass
the `SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13` constant to the fourth argument after the
password, salt, and security level.

```diff
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('correct horse barry staple'),
-             "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
+             "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
+             KeyFactory::INTERACTIVE,
+             SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        );
```

If you previously specified a security level, your diff might look like this:

```diff
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('correct horse barry staple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
-             KeyFactory::SENSITIVE
+             KeyFactory::SENSITIVE,
+             SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        );
```

## Version 4.0.2 (2017-12-08)

This is mostly a boyscouting/documentation release. However, we now pass Psalm under the
strictest setting (`totallyTyped = true`). This means that not only is our public interface
totally type-safe, but Halite's internals are as well.

## Version 4.0.1 (2017-10-19)

* Prompted by [#67](https://github.com/paragonie/halite/issues/67), Halite is now available
  under the terms of the Mozilla Public License 2.0 (MPL-2.0). Using Halite to build products
  that restrict user freedom (such as DRM) is highly discouraged, but not forbidden.

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
