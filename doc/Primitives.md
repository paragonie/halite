# Cryptography Primitives used in Halite

* Symmetric-key encryption: [**XSalsa20**](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-stream) (note: only [authenticated encryption](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken) is available through Halite)
* Symmetric-key authentication: **[BLAKE2b](https://download.libsodium.org/doc/hashing/generic_hashing.html#singlepart-example-with-a-key)** (keyed)
* Asymmetric-key encryption: [**X25519**](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-scalarmult) followed by symmetric-key authenticated encryption
* Asymmetric-key digital signatures: [**Ed25519**](https://paragonie.com/book/pecl-libsodium/read/05-publickey-crypto.md#crypto-sign)
* Checksums: [**BLAKE2b**](https://paragonie.com/book/pecl-libsodium/read/06-hashing.md#crypto-generichash)
* Key splitting: [**HKDF-BLAKE2b**](Classes/Util.md)
* Password-Based Key Derivation: [**Argon2**](https://paragonie.com/book/pecl-libsodium/read/07-password-hashing.md#crypto-pwhash-str)

In all cases, we follow an Encrypt then MAC construction, thus avoiding the [cryptographic doom principle](http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle).
