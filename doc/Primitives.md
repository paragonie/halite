# Cryptography Primitives used in Halite

* Symmetric-key encryption: [**Xsalsa20**](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-stream)
* Symmetric-key authentication: **[HMAC-SHA512/256](https://paragonie.com/book/pecl-libsodium/read/04-secretkey-crypto.md#crypto-auth)**
* Asymmetric-key encryption: [ECDH (**Curve25519**)](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-scalarmult) followed by symmetric-key encryption
* Asymmetric-key digital signatures: [**Ed25519**](https://paragonie.com/book/pecl-libsodium/read/05-publickey-crypto.md#crypto-sign)
* Checksums ([File](Classes/File.md) only): [**BLAKE2b**](https://paragonie.com/book/pecl-libsodium/read/06-hashing.md#crypto-generichash)
* Key splitting: [**HKDF**-like construction with **BLAKE2b**](Classes/Util.md)

In all cases, we Encrypt then MAC.