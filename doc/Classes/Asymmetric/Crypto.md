# \ParagonIE\Halite\Asymmetric\Crypto

## Methods

### `public` encrypt(`string $source`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `boolean $raw = false`) : `string`

This method will:

1. Calculate a shared symmetric encryption key between your secret key and your 
   recipient's public key.
2. Generate a random HKDF salt.
3. Split the shared secret using salted HKDF.
4. Generate a random nonce.
5. Encrypt your plaintext (`$source`) with the derived encryption key (step 3).
6. MAC the ciphertext (step 5), along with the currnet library version, the HKDF 
   salt, and the nonce, with the derived authentication key (step 3).
7. Return the output of step 6 either as raw binary or as a hex-encoded string.

### `public` decrypt(`string $source`, [`EncryptionSecretKey`](EncryptionSecretKey.md) `$ourPrivateKey`, [`EncryptionPublicKey`](EncryptionPublicKey.md) `$theirPublicKey`, `boolean $raw = false`) : `string`

This method will:

1. If we aren't expecting raw data, we treat `$source` as a hex string and
   decode it to raw binary.
2. Calculate a shared symmetric encryption key between your secret key and the
   sender's public key.
3. Parse the library version tag, HKDF salt, and nonce from the message.
4. Split the shared secret using salted HKDF.
5. Verify the MAC using the derived authentication key (step 4).
6. If step 4 is successful, decrypt the ciphertext with the derived encryption 
   key (step 4).
7. Return what should be the original plaintext.

