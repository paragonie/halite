# Crypto (abstract)

**Namespace**: `\ParagonIE\Halite\Symmetric`

## Methods

### `authenticate()`

> `public` authenticate(`string $message`, [`AuthenticationKey`](AuthenticationKey.md) `$secretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `string`

Calculate a MAC for a given message, using a secret authentication key.

### `encrypt()`

> `public` encrypt(`HiddenString $plaintext`, [`EncryptionKey`](EncryptionKey.md) `$secretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`): `string`

Encrypt-then-authenticate a message. This method will:

1. Generate a random HKDF salt.
2. Split the [`EncryptionKey`](EncryptionKey.md) into an encryption key and 
   authentication key using salted HKDF.
3. Generate a random nonce.
4. Encrypt your plaintext (`$source`) with the derived encryption key (step 2).
5. MAC the ciphertext (step 4), along with the current library version, the HKDF
   salt, and the nonce, with the derived authentication key (step 2).
6. Return the output of step 5 either as raw binary or as a hex-encoded string.

### `decrypt()`

> `public` decrypt(`string $ciphertext`, [`EncryptionKey`](EncryptionKey.md) `$secretKey`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `HiddenString`

Verify-then-decrypt a message. This method will:

1. If we aren't expecting raw data, we treat `$source` as a hex string and
   decode it to raw binary.
2. Parse the library version tag, HKDF salt, and nonce from the message.
3. Split the [`EncryptionKey`](EncryptionKey.md) into an encryption key and 
   authentication key using salted HKDF.
4. Verify the MAC using the derived authentication key (step 3).
5. If step 4 is successful, decrypt the ciphertext with the derived encryption 
   key (step 3).
6. Return what should be the original plaintext.

### `encryptWithAd()`

> `public` encryptWithAd(`HiddenString $plaintext`, [`EncryptionKey`](EncryptionKey.md) `$secretKey`, `string $additionalData = ''`, `$encoding = Halite::ENCODE_BASE64URLSAFE`): `string`

This is similar to `encrypt()`, except the `$additionalData` string is prepended to the ciphertext (after the nonce) when calculating the Message Authentication Code (MAC).

### `decryptWithAd()`

> `public` decryptWithAd(`string $ciphertext`, [`EncryptionKey`](EncryptionKey.md) `$secretKey`, `string $additionalData = ''`, `$encoding = Halite::ENCODE_BASE64URLSAFE`): `HiddenString`

This is similar to `decrypt()`, except the `$additionalData` string is prepended to the ciphertext (after the nonce) when calculating the Message Authentication Code (MAC).

### `verify()`

> `public` verify(`string $message`, [`AuthenticationKey`](AuthenticationKey.md) `$secretKey`, `string $mac`, `$encoding = Halite::ENCODE_BASE64URLSAFE`) : `boolean`

Verify the MAC for a given message and secret authentication key.