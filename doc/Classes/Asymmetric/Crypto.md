# Crypto (abstract)

**Namespace**: `\ParagonIE\Halite\Asymmetric`

## Methods

### `getSharedSecret()`

> `public` getSharedSecret([`EncryptionSecretKey`](EncryptionSecretKey.md) `$privateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$publicKey`, `$get_as_object = false`) : [`EncryptionKey`](../Symmetric/EncryptionKey.md)

This method calculates a shared [`EncryptionKey`](../Symmetric/EncryptionKey.md)
using X25519 (Elliptic Curve Diffie Hellman key agreement over Curve25519).

### `encrypt()`

> `public` encrypt(`HiddenString $source`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `string`

This method will:

1. Calculate a shared symmetric encryption key between your secret key and your 
   recipient's public key.
2. Generate a random HKDF salt.
3. Split the shared secret using salted HKDF.
4. Generate a random nonce.
5. Encrypt your plaintext (`$source`) with the derived encryption key (step 3).
6. MAC the ciphertext (step 5), along with the current library version, the HKDF 
   salt, and the nonce, with the derived authentication key (step 3).
7. Return the output of step 6 either as raw binary or as a hex-encoded string.

### `decrypt()`

> `public` decrypt(`string $source`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `HiddenString`

This method will:

1. If we aren't expecting raw data, we treat `$source` as a hex string and
   decode it to raw binary.
2. Calculate a shared symmetric encryption key between your secret key and the
   sender's public key.
3. Parse the library version tag, HKDF salt, and nonce from the message.
4. Split the shared secret using salted HKDF.
5. Verify the MAC using the derived authentication key (step 4).
6. If step 5 is successful, decrypt the ciphertext with the derived encryption 
   key (step 4).
7. Return what should be the original plaintext.

### `encryptWithAd()`

> `public` encryptWithAd(`HiddenString $plaintext`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `string $additionalData = ''`, `$encoding = Halite::ENCODE_BASE64URLSAFE`): `string`

This is similar to `encrypt()`, except the `$additionalData` string is prepended to the ciphertext (after the nonce) when calculating the Message Authentication Code (MAC).

### `decryptWithAd()`

> `public` decryptWithAd(`string $ciphertext`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `string $additionalData = ''`, `$encoding = Halite::ENCODE_BASE64URLSAFE`): `HiddenString`

This is similar to `decrypt()`, except the `$additionalData` string is prepended to the ciphertext (after the nonce) when calculating the Message Authentication Code (MAC).

### `seal()`

> `public` seal(`HiddenString $source`,  [`EncryptionPublicKey`](EncryptionPublicKey.md) `$publicKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `string`

Anonymous public-key encryption. Encrypt a message with your recipient's public
key and they can use their secret key to decrypt it.

The actual underlying protocol is [`sodium_crypto_box_seal()`](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-box-seal).

### `unseal()`

> `public` unseal(`string $source`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$secretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `HiddenString`

Anonymous public-key decryption. Decrypt a sealed message with your secret key.

The actual underlying protocol is [`sodium_crypto_box_seal_open()`](https://paragonie.com/book/pecl-libsodium/read/08-advanced.md#crypto-box-seal).

### `sign()`

> `public` sign(`string $message`, [`SignatureSecretKey`](SignatureSecretKey.md) `$secretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `string`

Calculates a digital signature of `$message`, using [`sodium_crypto_sign()`](https://paragonie.com/book/pecl-libsodium/read/05-publickey-crypto.md#crypto-sign).

### `verify()`

> `public` verify(`string $message`, [`SignaturePublicKey`](SignaturePublicKey.md) `$secretKey`, `string $signature`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `boolean`

Does the signature match the contents of the message, for the given public key?

### `signAndEncrypt()`

> `public` signAndEncrypt(`HiddenString $message`, [`SignatureSecretKey`](SignatureSecretKey.md) `$secretKey`, [`PublicKey`](PublicKey.md) `$recipientPublicKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `string`

Signs and encrypts a message. Note that a `SignaturePublicKey` or `EncryptionPublicKey`
is acceptable for the third argument. This is intended to facilitate the GPG use-case.

> `public` verifyAndDecrypt(`string $message`, [`SignaturePublicKey`](SignaturePublicKey.md) `$secretKey`, [`SecretKey`](SecretKey.md) `$mySecretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `HiddenString`

Decrypts and verifies a message. Note that a `SignatureSecretKey` or `EncryptionSecretKey`
is acceptable for the third argument. This is intended to facilitate the GPG use-case.
