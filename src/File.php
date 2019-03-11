<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    FileAccessDenied,
    FileError,
    FileModified,
    InvalidDigestLength,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    InvalidType
};
use ParagonIE\Halite\{
    Asymmetric\Crypto as AsymmetricCrypto,
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Contract\StreamInterface,
    Stream\MutableFile,
    Stream\ReadOnlyFile,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey
};
use ParagonIE\HiddenString\HiddenString;

/**
 * Class File
 *
 * Cryptography operations for the filesystem.
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class File
{
    /**
     * Don't allow this to be instantiated.
     *
     * @throws \Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Calculate the BLAKE2b-512 checksum of a file. This method doesn't load
     * the entire file into memory. You may optionally supply a key to use in
     * the BLAKE2b hash.
     *
     * @param string|resource|ReadOnlyFile $filePath
     * @param Key $key (optional; expects SignaturePublicKey or
     *                  AuthenticationKey)
     * @param mixed $encoding Which encoding scheme to use for the checksum?
     * @return string         The checksum
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function checksum(
        $filePath,
        Key $key = null,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        if ($filePath instanceof ReadOnlyFile) {
            $pos = $filePath->getPos();
            $filePath->reset(0);
            $checksum = self::checksumData(
                $filePath,
                $key,
                $encoding
            );
            $filePath->reset($pos);
            return $checksum;
        }

        if (\is_resource($filePath) || \is_string($filePath)) {
            $readOnly = new ReadOnlyFile($filePath);
            try {
                $checksum = self::checksumData(
                    $readOnly,
                    $key,
                    $encoding
                );
                return $checksum;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Encrypt a file using symmetric authenticated encryption.
     *
     * @param string|resource|ReadOnlyFile $input Input file
     * @param string|resource|MutableFile $output Output file
     * @param EncryptionKey $key                  Symmetric encryption key
     * @return int                                Number of bytes written
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function encrypt(
        $input,
        $output,
        EncryptionKey $key
    ): int {
        if (
            (\is_resource($input) || \is_string($input) || ($input instanceof ReadOnlyFile))
                &&
            (\is_resource($output) || \is_string($output) || ($output instanceof MutableFile))
        ) {
            try {
                if ($input instanceof ReadOnlyFile) {
                    $readOnly = $input;
                } else {
                    $readOnly = new ReadOnlyFile($input);
                }
                if ($output instanceof MutableFile) {
                    $mutable = $output;
                } else {
                    $mutable = new MutableFile($output);
                }
                $data = self::encryptData(
                    $readOnly,
                    $mutable,
                    $key
                );
                return $data;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
                if (isset($mutable)) {
                    $mutable->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Decrypt a file using symmetric-key authenticated encryption.
     *
     * @param string|resource|ReadOnlyFile $input Input file
     * @param string|resource|MutableFile $output Output file
     * @param EncryptionKey $key                  Symmetric encryption key
     * @return bool                               TRUE if successful
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function decrypt(
        $input,
        $output,
        EncryptionKey $key
    ): bool {
        if (
            (\is_resource($input) || \is_string($input) || ($input instanceof ReadOnlyFile))
                &&
            (\is_resource($output) || \is_string($output) || ($output instanceof MutableFile))
        ) {
            try {
                if ($input instanceof ReadOnlyFile) {
                    $readOnly = $input;
                } else {
                    $readOnly = new ReadOnlyFile($input);
                }
                if ($output instanceof MutableFile) {
                    $mutable = $output;
                } else {
                    $mutable = new MutableFile($output);
                }
                $data = self::decryptData(
                    $readOnly,
                    $mutable,
                    $key
                );
                return $data;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
                if (isset($mutable)) {
                    $mutable->close();
                }
            }
        }
        throw new InvalidType(
            'Strings or file handles expected'
        );
    }

    /**
     * Encrypt a file using anonymous public-key encryption (with ciphertext
     * authentication).
     *
     * @param string|resource|ReadOnlyFile $input Input file
     * @param string|resource|MutableFile $output Output file
     * @param EncryptionPublicKey $publicKey      Recipient's encryption public key
     * @return int
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \Exception
     * @throws \TypeError
     */
    public static function seal(
        $input,
        $output,
        EncryptionPublicKey $publicKey
    ): int {
        if (
            (\is_resource($input) || \is_string($input) || ($input instanceof ReadOnlyFile))
                &&
            (\is_resource($output) || \is_string($output) || ($output instanceof MutableFile))
        ) {
            try {
                if ($input instanceof ReadOnlyFile) {
                    $readOnly = $input;
                } else {
                    $readOnly = new ReadOnlyFile($input);
                }
                if ($output instanceof MutableFile) {
                    $mutable = $output;
                } else {
                    $mutable = new MutableFile($output);
                }
                $data = self::sealData(
                    $readOnly,
                    $mutable,
                    $publicKey
                );
                return $data;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
                if (isset($mutable)) {
                    $mutable->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Decrypt a file using anonymous public-key encryption. Ciphertext
     * integrity is still assured thanks to the Encrypt-then-MAC construction.
     *
     * @param string|resource|ReadOnlyFile $input Input file
     * @param string|resource|MutableFile $output Output file
     * @param EncryptionSecretKey $secretKey      Recipient's encryption secret key
     * @return bool                               TRUE on success
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function unseal(
        $input,
        $output,
        EncryptionSecretKey $secretKey
    ): bool {
        if (
            (\is_resource($input) || \is_string($input) || ($input instanceof ReadOnlyFile))
                &&
            (\is_resource($output) || \is_string($output) || ($output instanceof MutableFile))
        ) {
            try {
                if ($input instanceof ReadOnlyFile) {
                    $readOnly = $input;
                } else {
                    $readOnly = new ReadOnlyFile($input);
                }
                if ($output instanceof MutableFile) {
                    $mutable = $output;
                } else {
                    $mutable = new MutableFile($output);
                }
                $data = self::unsealData(
                    $readOnly,
                    $mutable,
                    $secretKey
                );
                return $data;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
                if (isset($mutable)) {
                    $mutable->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Calculate a digital signature (Ed25519) of a file
     *
     * Specifically:
     * 1. Calculate the BLAKE2b-512 checksum of the file, with the signer's
     *    Ed25519 public key used as a BLAKE2b key.
     * 2. Sign the checksum with Ed25519, using the corresponding public key.
     *
     * @param string|resource|ReadOnlyFile $filename     File name or file handle
     * @param SignatureSecretKey $secretKey Secret key for digital signatures
     * @param mixed $encoding               Which encoding scheme to use for the signature?
     * @return string                       Detached signature for the file
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function sign(
        $filename,
        SignatureSecretKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        if ($filename instanceof ReadOnlyFile) {
            $pos = $filename->getPos();
            $filename->reset(0);
            $signature = self::signData(
                $filename,
                $secretKey,
                $encoding
            );
            $filename->reset($pos);
            return $signature;
        }
        if (\is_resource($filename) || \is_string($filename)) {
            $readOnly = new ReadOnlyFile($filename);
            try {
                $signature = self::signData(
                    $readOnly,
                    $secretKey,
                    $encoding
                );
                return $signature;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Verify a digital signature for a file.
     *
     * @param string|resource|ReadOnlyFile $filename     File name or file handle
     * @param SignaturePublicKey $publicKey Other party's signature public key
     * @param string $signature             The signature we received
     * @param mixed $encoding               Which encoding scheme to use for the signature?
     *
     * @return bool
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function verify(
        $filename,
        SignaturePublicKey $publicKey,
        string $signature,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): bool {
        if ($filename instanceof ReadOnlyFile) {
            $pos = $filename->getPos();
            $filename->reset(0);
            $verified = self::verifyData(
                $filename,
                $publicKey,
                $signature,
                $encoding
            );
            $filename->reset($pos);
            return $verified;
        }
        if (\is_resource($filename) || \is_string($filename)) {
            $readOnly = new ReadOnlyFile($filename);
            try {
                $verified = self::verifyData(
                    $readOnly,
                    $publicKey,
                    $signature,
                    $encoding
                );
                return $verified;
            } finally {
                if (isset($readOnly)) {
                    $readOnly->close();
                }
            }
        }
        throw new InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Calculate the BLAKE2b checksum of the contents of a file
     *
     * @param StreamInterface $fileStream
     * @param Key $key
     * @param mixed $encoding Which encoding scheme to use for the checksum?
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     * @throws \SodiumException
     */
    protected static function checksumData(
        StreamInterface $fileStream,
        Key $key = null,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $config = self::getConfig(
            Halite::HALITE_VERSION_FILE,
            'checksum'
        );

        // 1. Initialize the hash context
        if ($key instanceof AuthenticationKey) {
            // AuthenticationKey is for HMAC, but we can use it for keyed hashes too
            $state = \sodium_crypto_generichash_init(
                $key->getRawKeyMaterial(),
                (int) $config->HASH_LEN
            );
        } elseif($config->CHECKSUM_PUBKEY && ($key instanceof SignaturePublicKey)) {
            // In version 2, we use the public key as a hash key
            $state = \sodium_crypto_generichash_init(
                $key->getRawKeyMaterial(),
                (int) $config->HASH_LEN
            );
        // @codeCoverageIgnoreStart
        } elseif (isset($key)) {
        // @codeCoverageIgnoreEnd
            throw new InvalidKey(
                'Argument 2: Expected an instance of AuthenticationKey or SignaturePublicKey'
            );
        } else {
            $state = \sodium_crypto_generichash_init(
                '',
                (int) $config->HASH_LEN
            );
        }

        // 2. Calculate the hash
        $size = $fileStream->getSize();
        while ($fileStream->remainingBytes() > 0) {
            // Don't go past the file size even if $config->BUFFER is not an even multiple of it:
            if (($fileStream->getPos() + (int) $config->BUFFER) > $size) {
                /** @var int $amount_to_read */
                $amount_to_read = ($size - $fileStream->getPos());
            } else {
                // @codeCoverageIgnoreStart
                /** @var int $amount_to_read */
                $amount_to_read = (int) $config->BUFFER;
                // @codeCoverageIgnoreEnd
            }
            $read = $fileStream->readBytes($amount_to_read);
            \sodium_crypto_generichash_update($state, $read);
        }

        // 3. Do we want a raw checksum?
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return (string) $encoder(
                \sodium_crypto_generichash_final(
                    // @codeCoverageIgnoreStart
                    $state,
                    // @codeCoverageIgnoreEnd
                    (int) $config->HASH_LEN
                )
            );
        }
        return (string) \sodium_crypto_generichash_final(
            // @codeCoverageIgnoreStart
            $state,
            // @codeCoverageIgnoreEnd
            (int) $config->HASH_LEN
        );
    }

    /**
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionKey $key
     * @return int
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     * @throws \SodiumException
     */
    protected static function encryptData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionKey $key
    ): int {
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'encrypt');

        // Generate a nonce and HKDF salt
        // @codeCoverageIgnoreStart
        try {
            $firstNonce = \random_bytes((int) $config->NONCE_BYTES);
            $hkdfSalt = \random_bytes((int) $config->HKDF_SALT_LEN);
        } catch (\Throwable $ex) {
            throw new CannotPerformOperation($ex->getMessage());
        }
        // @codeCoverageIgnoreEnd

        // Let's split our key
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);

        // Write the header
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $firstNonce,
            \SODIUM_CRYPTO_STREAM_NONCEBYTES
        );
        $output->writeBytes(
            $hkdfSalt,
            (int) $config->HKDF_SALT_LEN
        );

        // VERSION 2+ uses BMAC
        $mac = \sodium_crypto_generichash_init($authKey);
        \sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
        \sodium_crypto_generichash_update($mac, $firstNonce);
        \sodium_crypto_generichash_update($mac, $hkdfSalt);
        /** @var string $mac */

        \sodium_memzero($authKey);
        \sodium_memzero($hkdfSalt);

        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            (string) $firstNonce,
            (string) $mac,
            $config
        );
    }

    /**
     * Decrypt the contents of a file.
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionKey $key
     * @return bool
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \SodiumException
     */
    protected static function decryptData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionKey $key
    ): bool {
        // Rewind
        $input->reset(0);

        // Make sure it's large enough to even read a version tag
        if ($input->getSize() < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }
        // Parse the header, ensuring we get 4 bytes
        /** @var string $header */
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);

        // Load the config
        $config = self::getConfig($header, 'encrypt');

        // Is this shorter than an encrypted empty string?
        if ($input->getSize() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }

        // Let's grab the first nonce and salt
        /** @var string $firstNonce */
        $firstNonce = $input->readBytes((int) $config->NONCE_BYTES);
        /** @var string $hkdfSalt */
        $hkdfSalt = $input->readBytes((int) $config->HKDF_SALT_LEN);

        // Split our keys, begin the HMAC instance
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);

        // VERSION 2+ uses BMAC
        $mac = \sodium_crypto_generichash_init($authKey);
        \sodium_crypto_generichash_update($mac, $header);
        \sodium_crypto_generichash_update($mac, $firstNonce);
        \sodium_crypto_generichash_update($mac, $hkdfSalt);
        /** @var string $mac */

        $old_macs = self::streamVerify($input, Util::safeStrcpy($mac), $config);

        \sodium_memzero($authKey);
        \sodium_memzero($hkdfSalt);

        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            (string) $firstNonce,
            (string) $mac,
            $config,
            $old_macs
        );

        \sodium_memzero($encKey);
        unset($encKey);
        unset($authKey);
        unset($firstNonce);
        unset($mac);
        unset($config);
        unset($old_macs);

        return $ret;
    }

    /**
     * Seal the contents of a file.
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionPublicKey $publicKey
     * @return int
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \Exception
     * @throws \TypeError
     */
    protected static function sealData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionPublicKey $publicKey
    ): int {
        // Generate a new keypair for this encryption
        $ephemeralKeyPair = KeyFactory::generateEncryptionKeyPair();
        $ephSecret = $ephemeralKeyPair->getSecretKey();
        $ephPublic = $ephemeralKeyPair->getPublicKey();
        unset($ephemeralKeyPair);

        // Calculate the shared secret key
        $sharedSecretKey = AsymmetricCrypto::getSharedSecret($ephSecret, $publicKey, true);
        // @codeCoverageIgnoreStart
        if (!($sharedSecretKey instanceof EncryptionKey)) {
            throw new \TypeError('Shared secret is the wrong key type.');
        }
        // @codeCoverageIgnoreEnd

        // Destroy the secret key after we have the shared secret
        unset($ephSecret);

        // Load the configuration
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'seal');

        // Generate a nonce as per crypto_box_seal
        $nonce = \sodium_crypto_generichash(
            $ephPublic->getRawKeyMaterial() . $publicKey->getRawKeyMaterial(),
            '',
            \SODIUM_CRYPTO_STREAM_NONCEBYTES
        );

        // Generate a random HKDF salt
        $hkdfSalt = \random_bytes((int) $config->HKDF_SALT_LEN);

        // Split the keys
        /**
         * @var string $encKey
         * @var string $authKey
         */
        list ($encKey, $authKey) = self::splitKeys($sharedSecretKey, $hkdfSalt, $config);

        // Write the header:
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $ephPublic->getRawKeyMaterial(),
            \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES
        );
        $output->writeBytes(
            $hkdfSalt,
            (int) $config->HKDF_SALT_LEN
        );

        // VERSION 2+
        $mac = \sodium_crypto_generichash_init($authKey);

        // We no longer need $authKey after we set up the hash context
        \sodium_memzero($authKey);

        \sodium_crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
        \sodium_crypto_generichash_update($mac, $ephPublic->getRawKeyMaterial());
        \sodium_crypto_generichash_update($mac, $hkdfSalt);

        unset($ephPublic);
        \sodium_memzero($hkdfSalt);

        $ret = self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            (string) $nonce,
            (string) $mac,
            $config
        );
        \sodium_memzero($encKey);
        unset($encKey);
        unset($nonce);
        return $ret;
    }

    /**
     * Unseal the contents of a file.
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionSecretKey $secretKey
     * @return bool
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws FileModified
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    protected static function unsealData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionSecretKey $secretKey
    ): bool {
        $publicKey = $secretKey
            ->derivePublicKey();

        // Is the file at least as long as a header?
        if ($input->getSize() < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }

        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);

        // Load the config
        $config = self::getConfig($header, 'seal');

        if ($input->getSize() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }
        // Let's grab the public key and salt
        $ephPublic = $input->readBytes((int) $config->PUBLICKEY_BYTES);
        $hkdfSalt = $input->readBytes((int) $config->HKDF_SALT_LEN);

        // Generate the same nonce, as per sealData()
        $nonce = \sodium_crypto_generichash(
            $ephPublic . $publicKey->getRawKeyMaterial(),
            '',
            \SODIUM_CRYPTO_STREAM_NONCEBYTES
        );

        // Create a key object out of the public key:
        $ephemeral = new EncryptionPublicKey(
            new HiddenString($ephPublic)
        );

        $key = AsymmetricCrypto::getSharedSecret(
            $secretKey,
            $ephemeral,
            true
        );
        // @codeCoverageIgnoreStart
        if (!($key instanceof EncryptionKey)) {
            throw new \TypeError();
        }
        // @codeCoverageIgnoreEnd
        unset($ephemeral);

        /**
         * @var string $encKey
         * @var string $authKey
         */
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);
        // We no longer need the original key after we split it
        unset($key);

        $mac = \sodium_crypto_generichash_init($authKey);

        \sodium_crypto_generichash_update($mac, $header);
        \sodium_crypto_generichash_update($mac, $ephPublic);
        \sodium_crypto_generichash_update($mac, $hkdfSalt);

        /** @var string $mac */
        $oldMACs = self::streamVerify($input, Util::safeStrcpy($mac), $config);

        // We no longer need these:
        \sodium_memzero($authKey);
        \sodium_memzero($hkdfSalt);

        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            $nonce,
            $mac,
            $config,
            $oldMACs
        );

        \sodium_memzero($encKey);
        unset($encKey);
        unset($nonce);
        unset($mac);
        unset($config);
        unset($oldMACs);
        return $ret;
    }

    /**
     * Sign the contents of a file
     *
     * @param ReadOnlyFile $input
     * @param SignatureSecretKey $secretKey
     * @param mixed $encoding Which encoding scheme to use for the signature?
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    protected static function signData(
        ReadOnlyFile $input,
        SignatureSecretKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $checksum = self::checksumData(
            $input,
            $secretKey->derivePublicKey(),
            true
        );
        return AsymmetricCrypto::sign(
            $checksum,
            $secretKey,
            $encoding
        );
    }

    /**
     * Verify the contents of a file
     *
     * @param $input (file handle)
     * @param SignaturePublicKey $publicKey
     * @param string $signature
     * @param mixed $encoding Which encoding scheme to use for the signature?
     *
     * @return bool
     *
     * @throws InvalidSignature
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    protected static function verifyData(
        ReadOnlyFile $input,
        SignaturePublicKey $publicKey,
        string $signature,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): bool {
        $checksum = self::checksumData($input, $publicKey, true);
        return AsymmetricCrypto::verify(
            $checksum,
            $publicKey,
            $signature,
            $encoding
        );
    }

    /**
     * Get the configuration
     *
     * @param string $header
     * @param string $mode
     * @return Config
     * @throws InvalidMessage
     * @throws InvalidType
     */
    protected static function getConfig(
        string $header,
        string $mode = 'encrypt'
    ): Config {
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 65) {
            // @codeCoverageIgnoreStart
            throw new InvalidMessage(
                'Invalid version tag'
            );
            // @codeCoverageIgnoreEnd
        }
        $major = \ord($header[2]);
        $minor = \ord($header[3]);
        if ($mode === 'encrypt') {
            return new Config(
                self::getConfigEncrypt($major, $minor)
            );
        } elseif ($mode === 'seal') {
            return new Config(
                self::getConfigSeal($major, $minor)
            );
        } elseif ($mode === 'checksum') {
            return new Config(
                self::getConfigChecksum($major, $minor)
            );
        }
        // @codeCoverageIgnoreStart
        throw new InvalidType(
            'Invalid configuration mode'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Get the configuration for encrypt operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws InvalidMessage
     */
    protected static function getConfigEncrypt(int $major, int $minor): array
    {

        if ($major === 4) {
            return [
                'SHORTEST_CIPHERTEXT_LENGTH' => 92,
                'BUFFER' => 1048576,
                'NONCE_BYTES' => \SODIUM_CRYPTO_STREAM_NONCEBYTES,
                'HKDF_SALT_LEN' => 32,
                'MAC_SIZE' => 32,
                'HKDF_SBOX' => 'Halite|EncryptionKey',
                'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
            ];
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 92,
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \SODIUM_CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        // If we reach here, we've got an invalid version tag:
        // @codeCoverageIgnoreStart
        throw new InvalidMessage(
            'Invalid version tag'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Get the configuration for seal operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws InvalidMessage
     */
    protected static function getConfigSeal(int $major, int $minor): array
    {
        if ($major === 4) {
            switch ($minor) {
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 100,
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 100,
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        // @codeCoverageIgnoreStart
        throw new InvalidMessage(
            'Invalid version tag'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Get the configuration for encrypt operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws InvalidMessage
     */
    protected static function getConfigChecksum(int $major, int $minor): array
    {
        if ($major === 3 || $major === 4) {
            switch ($minor) {
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => true,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        }
        // @codeCoverageIgnoreStart
        throw new InvalidMessage(
            'Invalid version tag'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Split a key using HKDF-BLAKE2b
     *
     * @param Key $master
     * @param string $salt
     * @param Config $config
     * @return array<int, string>
     *
     * @throws InvalidDigestLength
     * @throws CannotPerformOperation
     * @throws \TypeError
     */
    protected static function splitKeys(
        Key $master,
        string $salt,
        Config $config
    ): array {
        $binary = $master->getRawKeyMaterial();
        return [
            Util::hkdfBlake2b(
                $binary,
                \SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                (string) $config->HKDF_SBOX,
                $salt
            ),
            Util::hkdfBlake2b(
                $binary,
                \SODIUM_CRYPTO_AUTH_KEYBYTES,
                (string) $config->HKDF_AUTH,
                $salt
            )
        ];
    }

    /**
     * Stream encryption - Do not call directly
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionKey $encKey
     * @param string $nonce
     * @param string $mac (hash context for BLAKE2b)
     * @param Config $config
     *
     * @return int (number of bytes)
     *
     * @throws FileError
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws \SodiumException
     * @throws \TypeError
     */
    final private static function streamEncrypt(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionKey $encKey,
        string $nonce,
        string $mac,
        Config $config
    ): int {
        $initHash = $input->getHash();
        // Begin the streaming decryption
        $size = $input->getSize();
        $written = 0;
        while ($input->remainingBytes() > 0) {
            $read = $input->readBytes(
                ($input->getPos() + (int) $config->BUFFER) > $size
                    ? ($size - $input->getPos())
                    : (int) $config->BUFFER
            );

            $encrypted = \sodium_crypto_stream_xor(
                $read,
                (string) $nonce,
                $encKey->getRawKeyMaterial()
            );
            \sodium_crypto_generichash_update($mac, $encrypted);
            $written += $output->writeBytes($encrypted);
            \sodium_increment($nonce);
        }
        if (\is_string($nonce)) {
            \sodium_memzero($nonce);
        }

        // Check that our input file was not modified before we MAC it
        if (!\hash_equals($input->getHash(), $initHash)) {
            // @codeCoverageIgnoreStart
            throw new FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
            // @codeCoverageIgnoreEnd
        }
        $written += $output->writeBytes(
            \sodium_crypto_generichash_final($mac, (int) $config->MAC_SIZE),
            (int) $config->MAC_SIZE
        );
        return $written;
    }

    /**
     * Stream decryption - Do not call directly
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionKey $encKey
     * @param string $nonce
     * @param string $mac (hash context for BLAKE2b)
     * @param Config $config
     * @param array &$chunk_macs
     *
     * @return bool
     *
     * @throws FileError
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidMessage
     * @throws \TypeError
     * @throws \SodiumException
     */
    final private static function streamDecrypt(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionKey $encKey,
        string $nonce,
        string $mac,
        Config $config,
        array &$chunk_macs
    ): bool {
        $start = $input->getPos();
        /** @var int $cipher_end */
        $cipher_end = $input->getSize() - (int) $config->MAC_SIZE;
        // Begin the streaming decryption
        $input->reset($start);

        while ($input->remainingBytes() > (int) $config->MAC_SIZE) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if (($input->getPos() + (int) $config->BUFFER) > $cipher_end) {
                $read = $input->readBytes(
                    $cipher_end - $input->getPos()
                );
            } else {
                // @codeCoverageIgnoreStart
                $read = $input->readBytes((int) $config->BUFFER);
                // @codeCoverageIgnoreEnd
            }

            // Version 2+ uses a keyed BLAKE2b hash instead of HMAC
            \sodium_crypto_generichash_update($mac, $read);
            /** @var string $mac */
            $calcMAC = Util::safeStrcpy($mac);
            $calc = \sodium_crypto_generichash_final($calcMAC, (int) $config->MAC_SIZE);

            if (empty($chunk_macs)) {
                // @codeCoverageIgnoreStart
                // Someone attempted to add a chunk at the end.
                throw new InvalidMessage(
                    'Invalid message authentication code'
                );
                // @codeCoverageIgnoreEnd
            } else {
                /** @var string $chunkMAC */
                $chunkMAC = \array_shift($chunk_macs);
                if (!\hash_equals($chunkMAC, $calc)) {
                    // This chunk was altered after the original MAC was verified
                    // @codeCoverageIgnoreStart
                    throw new InvalidMessage(
                        'Invalid message authentication code'
                    );
                    // @codeCoverageIgnoreEnd
                }
            }

            // This is where the decryption actually occurs:
            $decrypted = \sodium_crypto_stream_xor(
                $read,
                (string) $nonce,
                $encKey->getRawKeyMaterial()
            );
            $output->writeBytes($decrypted);
            \sodium_increment($nonce);
        }
        if (\is_string($nonce)) {
            \sodium_memzero($nonce);
        }
        return true;
    }

    /**
     * Recalculate and verify the HMAC of the input file
     *
     * @param ReadOnlyFile $input  The file we are verifying
     * @param string $mac (hash context)
     * @param Config $config       Version-specific settings
     *
     * @return array               Hashes of various chunks
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
     * @throws InvalidMessage
     * @throws \TypeError
     * @throws \SodiumException
     */
    final private static function streamVerify(
        ReadOnlyFile $input,
        $mac,
        Config $config
    ): array {
        /** @var int $start */
        $start = $input->getPos();

        // Grab the stored MAC:
        /** @var int $cipher_end */
        $cipher_end = $input->getSize() - (int) $config->MAC_SIZE;
        $input->reset($cipher_end);
        $stored_mac = $input->readBytes((int) $config->MAC_SIZE);
        $input->reset($start);

        $chunkMACs = [];

        $break = false;
        while (!$break && $input->getPos() < $cipher_end) {

            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if (($input->getPos() + (int) $config->BUFFER) >= $cipher_end) {
                $break = true;
                $read = $input->readBytes($cipher_end - $input->getPos());
            } else {
                // @codeCoverageIgnoreStart
                $read = $input->readBytes((int) $config->BUFFER);
                // @codeCoverageIgnoreEnd
            }

            /**
             * We're updating our HMAC and nothing else
             */
            \sodium_crypto_generichash_update($mac, $read);
            $mac = (string) $mac;
            // Copy the hash state then store the MAC of this chunk
            /** @var string $chunkMAC */
            $chunkMAC = Util::safeStrcpy($mac);
            $chunkMACs []= \sodium_crypto_generichash_final(
                // @codeCoverageIgnoreStart
                $chunkMAC,
                // @codeCoverageIgnoreEnd
                (int) $config->MAC_SIZE
            );
        }

        /**
         * We should now have enough data to generate an identical MAC
         */
        $finalHMAC = \sodium_crypto_generichash_final(
            // @codeCoverageIgnoreStart
            $mac,
            // @codeCoverageIgnoreEnd
            (int) $config->MAC_SIZE
        );

        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!\hash_equals($finalHMAC, $stored_mac)) {
            throw new InvalidMessage(
                'Invalid message authentication code'
            );
        }
        $input->reset($start);
        return $chunkMACs;
    }
}
