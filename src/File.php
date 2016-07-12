<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;
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

/**
 * Class File
 *
 * Cryptography operations for the filesystem.
 *
 * @package ParagonIE\Halite
 */
final class File
{
    /**
     * Calculate the BLAKE2b-512 checksum of a file. This method doesn't load
     * the entire file into memory. You may optionally supply a key to use in
     * the BLAKE2b hash.
     *
     * @param string|resource $filePath The file
     * @param Key $key        (optional; expects SignaturePublicKey or
     *                         AuthenticationKey)
     * @param bool $raw       Defaults to returning a hexadecimal string.
     * @return string         The checksum
     * @throws CryptoException\InvalidType
     */
    public static function checksum(
        $filePath,
        Key $key = null,
        $raw = false
    ): string {
        if (\is_resource($filePath) || \is_string($filePath)) {
            $readOnly = new ReadOnlyFile($filePath);
            $checksum = self::checksumData(
                $readOnly,
                $key,
                $raw
            );
            $readOnly->close();
            return $checksum;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Encrypt a file using symmetric authenticated encryption.
     *
     * @param string|resource $input  File name or file handle
     * @param string|resource $output File name or file handle
     * @param EncryptionKey $key      Symmetric encryption key
     * @return int                    Number of bytes written
     * @throws CryptoException\InvalidType
     */
    public static function encrypt(
        $input,
        $output,
        EncryptionKey $key
    ): int {
        if (
            (\is_resource($input) || \is_string($input))
            &&
            (\is_resource($output) || \is_string($output))
        ) {
            $readOnly = new ReadOnlyFile($input);
            $mutable = new MutableFile($output);
            $data = self::encryptData(
                $readOnly,
                $mutable,
                $key
            );
            $readOnly->close();
            $mutable->close();
            return $data;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Decrypt a file using symmetric-key authenticated encryption.
     *
     * @param string|resource $input  File name or file handle
     * @param string|resource $output File name or file handle
     * @param EncryptionKey $key      Symmetric encryption key
     * @return bool                   TRUE if successful
     * @throws CryptoException\InvalidType
     */
    public static function decrypt(
        $input,
        $output,
        EncryptionKey $key
    ): bool {
        if (
            (\is_resource($input) || \is_string($input))
            &&
            (\is_resource($output) || \is_string($output))
        ) {
            try {
                $readOnly = new ReadOnlyFile($input);
                $mutable = new MutableFile($output);
                $data = self::decryptData(
                    $readOnly,
                    $mutable,
                    $key
                );
                return $data;
            } finally {
                $readOnly->close();
                $mutable->close();
            }
        }
        throw new CryptoException\InvalidType(
            'Strings or file handles expected'
        );
    }

    /**
     * Encrypt a file using anonymous public-key encryption (with ciphertext
     * authentication).
     *
     * @param string|resource $input         File name or file handle
     * @param string|resource $output        File name or file handle
     * @param EncryptionPublicKey $publicKey Recipient's encryption public key
     * @return int                           Number of bytes written
     * @throws Alerts\InvalidType
     */
    public static function seal(
        $input,
        $output,
        EncryptionPublicKey $publicKey
    ): int {
        if (
            (\is_resource($input) || \is_string($input))
            &&
            (\is_resource($output) || \is_string($output))
        ) {
            $readOnly = new ReadOnlyFile($input);
            $mutable = new MutableFile($output);
            $data = self::sealData(
                $readOnly,
                $mutable,
                $publicKey
            );
            $readOnly->close();
            $mutable->close();
            return $data;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Decrypt a file using anonymous public-key encryption. Ciphertext
     * integrity is still assured thanks to the Encrypt-then-MAC construction.
     *
     * @param string|resource $input         File name or file handle
     * @param string|resource $output        File name or file handle
     * @param EncryptionSecretKey $secretKey Recipient's encryption secret key
     * @return bool                          TRUE on success
     * @throws CryptoException\InvalidType
     */
    public static function unseal(
        $input,
        $output,
        EncryptionSecretKey $secretKey
    ): bool {
        if (
            (\is_resource($input) || \is_string($input))
            &&
            (\is_resource($output) || \is_string($output))
        ) {
            $readOnly = new ReadOnlyFile($input);
            $mutable = new MutableFile($output);
            try {
                $data = self::unsealData(
                    $readOnly,
                    $mutable,
                    $secretKey
                );
                return $data;
            } finally {
                $readOnly->close();
                $mutable->close();
            }
        }
        throw new CryptoException\InvalidType(
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
     * @param string|resource $filename     File name or file handle
     * @param SignatureSecretKey $secretKey Secret key for digital signatures
     * @param bool $raw_binary              Default: return hexadecimal
     * @return HiddenString                 Detached signature for the file
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     */
    public static function sign(
        $filename,
        SignatureSecretKey $secretKey,
        bool $raw_binary = false
    ): HiddenString {
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            $readOnly = new ReadOnlyFile($filename);
            $signature = self::signData(
                $readOnly,
                $secretKey,
                $raw_binary
            );
            $readOnly->close();
            return $signature;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Verify a digital signature for a file.
     *
     * @param string|resource $filename     File name or file handle
     * @param SignaturePublicKey $publicKey Other party's signature public key
     * @param string $signature             The signature we received
     * @param bool $raw_binary              TRUE if the signature is raw binary
     *
     * @return bool
     * @throws CryptoException\InvalidType
     */
    public static function verify(
        $filename,
        SignaturePublicKey $publicKey,
        HiddenString $signature,
        bool $raw_binary = false
    ): bool {
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            $readOnly = new ReadOnlyFile($filename);
            $verified = self::verifyData(
                $readOnly,
                $publicKey,
                $signature,
                $raw_binary
            );
            $readOnly->close();
            return $verified;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Calculate the BLAKE2b checksum of the contents of a file
     *
     * @param StreamInterface $fileStream
     * @param Key $key
     * @param bool $raw
     * @return string
     * @throws CryptoException\InvalidKey
     */
    protected static function checksumData(
        StreamInterface $fileStream,
        Key $key = null,
        bool $raw = false
    ): string {
        $config = self::getConfig(
            Halite::HALITE_VERSION_FILE,
            'checksum'
        );

        // 1. Initialize the hash context
        if ($key instanceof AuthenticationKey) {
            // AuthenticationKey is for HMAC, but we can use it for keyed hashes too
            $state = \Sodium\crypto_generichash_init(
                $key->getRawKeyMaterial(),
                $config->HASH_LEN
            );
        } elseif($config->CHECKSUM_PUBKEY && $key instanceof SignaturePublicKey) {
            // In version 2, we use the public key as a hash key
            $state = \Sodium\crypto_generichash_init(
                $key->getRawKeyMaterial(),
                $config->HASH_LEN
            );
        } elseif (isset($key)) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of AuthenticationKey or SignaturePublicKey'
            );
        } else {
            $state = \Sodium\crypto_generichash_init(
                '',
                $config->HASH_LEN
            );
        }

        // 2. Calculate the hash
        $size = $fileStream->getSize();
        while ($fileStream->remainingBytes() > 0) {
            // Don't go past the file size even if $config->BUFFER is not an even multiple of it:
            if (($fileStream->getPos() + $config->BUFFER) > $size) {
                $amount_to_read = ($size - $fileStream->getPos());
            } else {
                $amount_to_read = $config->BUFFER;
            }
            $read = $fileStream->readBytes($amount_to_read);
            \Sodium\crypto_generichash_update($state, $read);
        }

        // 3. Do we want a raw checksum?
        if ($raw) {
            return \Sodium\crypto_generichash_final(
                $state,
                $config->HASH_LEN
            );
        }
        return \Sodium\bin2hex(
            \Sodium\crypto_generichash_final(
                $state,
                $config->HASH_LEN
            )
        );
    }

    /**
     * Encrypt the contents of a file.
     *
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     * @return int
     */
    protected static function encryptData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionKey $key
    ): int {
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'encrypt');

        // Generate a nonce and HKDF salt
        $firstNonce = \Sodium\randombytes_buf($config->NONCE_BYTES);
        $hkdfSalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);

        // Let's split our key
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);

        // Write the header
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $firstNonce,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        $output->writeBytes(
            $hkdfSalt,
            $config->HKDF_SALT_LEN
        );

        // VERSION 2+
        $mac = \Sodium\crypto_generichash_init($authKey);
        \Sodium\crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
        \Sodium\crypto_generichash_update($mac, $firstNonce);
        \Sodium\crypto_generichash_update($mac, $hkdfSalt);

        \Sodium\memzero($authKey);
        \Sodium\memzero($hkdfSalt);

        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            $firstNonce,
            $mac,
            $config
        );
    }

    /**
     * Decrypt the contents of a file.
     *
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     * @return bool
     * @throws CryptoException\InvalidMessage
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
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }
        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);

        // Load the config
        $config = self::getConfig($header, 'encrypt');

        // Is this shorter than an encrypted empty string?
        if ($input->getSize() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }

        // Let's grab the first nonce and salt
        $firstNonce = $input->readBytes($config->NONCE_BYTES);
        $hkdfSalt = $input->readBytes($config->HKDF_SALT_LEN);

        // Split our keys, begin the HMAC instance
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);

        // VERSION 2+
        $mac = \Sodium\crypto_generichash_init($authKey);
        \Sodium\crypto_generichash_update($mac, $header);
        \Sodium\crypto_generichash_update($mac, $firstNonce);
        \Sodium\crypto_generichash_update($mac, $hkdfSalt);

        $old_macs = self::streamVerify($input, Util::safeStrcpy($mac), $config);

        \Sodium\memzero($authKey);
        \Sodium\memzero($hkdfSalt);

        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            $firstNonce,
            $mac,
            $config,
            $old_macs
        );

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

        // Destroy the secret key after we have the shared secret
        unset($ephSecret);

        // Load the configuration
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'seal');

        // Generate a nonce as per crypto_box_seal
        $nonce = \Sodium\crypto_generichash(
            $ephPublic->getRawKeyMaterial() . $publicKey->getRawKeyMaterial(),
            '',
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );

        // Generate a random HKDF salt
        $hkdfSalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);

        // Split the keys
        list ($encKey, $authKey) = self::splitKeys($sharedSecretKey, $hkdfSalt, $config);

        // We no longer need the original key after we split it
        unset($key);

        // Write the header:
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $ephPublic->getRawKeyMaterial(),
            \Sodium\CRYPTO_BOX_PUBLICKEYBYTES
        );
        $output->writeBytes(
            $hkdfSalt,
            $config->HKDF_SALT_LEN
        );

        // VERSION 2+
        $mac = \Sodium\crypto_generichash_init($authKey);

        // We no longer need $authKey after we set up the hash context
        \Sodium\memzero($authKey);

        \Sodium\crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
        \Sodium\crypto_generichash_update($mac, $ephPublic->getRawKeyMaterial());
        \Sodium\crypto_generichash_update($mac, $hkdfSalt);

        unset($ephPublic);
        \Sodium\memzero($hkdfSalt);

        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey(
                new HiddenString($encKey)
            ),
            $nonce,
            $mac,
            $config
        );
    }

    /**
     * Unseal the contents of a file.
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionSecretKey $secretKey
     * @return bool
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidMessage
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
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }

        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);

        // Load the config
        $config = self::getConfig($header, 'seal');

        if ($input->getSize() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }
        // Let's grab the public key and salt
        $ephPublic = $input->readBytes($config->PUBLICKEY_BYTES);
        $hkdfSalt = $input->readBytes($config->HKDF_SALT_LEN);

        // Generate the same nonce, as per sealData()
        $nonce = \Sodium\crypto_generichash(
            $ephPublic . $publicKey->getRawKeyMaterial(),
            '',
            \Sodium\CRYPTO_STREAM_NONCEBYTES
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
        unset($ephemeral);

        list ($encKey, $authKey) = self::splitKeys($key, $hkdfSalt, $config);
        // We no longer need the original key after we split it
        unset($key);

        $mac = \Sodium\crypto_generichash_init($authKey);

        \Sodium\crypto_generichash_update($mac, $header);
        \Sodium\crypto_generichash_update($mac, $ephPublic);
        \Sodium\crypto_generichash_update($mac, $hkdfSalt);

        $oldMACs = self::streamVerify($input, Util::safeStrcpy($mac), $config);
        // We no longer need this:
        \Sodium\memzero($hkdfSalt);

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

        unset($encKey);
        unset($authKey);
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
     * @param bool $raw_binary Don't hex encode?
     * @return HiddenString
     */
    protected static function signData(
        ReadOnlyFile $input,
        SignatureSecretKey $secretKey,
        bool $raw_binary = false
    ): HiddenString {
        $checksum = self::checksumData(
            $input,
            $secretKey->derivePublicKey(),
            true
        );
        if (\is_string($checksum)) {
            $checksum = new HiddenString($checksum);
        }
        return AsymmetricCrypto::sign(
            $checksum,
            $secretKey,
            $raw_binary
        );
    }

    /**
     * Verify the contents of a file
     *
     * @param $input (file handle)
     * @param SignaturePublicKey $publicKey
     * @param HiddenString $signature
     * @param bool $raw_binary Don't hex encode?
     *
     * @return bool
     */
    protected static function verifyData(
        ReadOnlyFile $input,
        SignaturePublicKey $publicKey,
        HiddenString $signature,
        bool $raw_binary = false
    ): bool {
        $checksum = self::checksumData($input, $publicKey, true);
        return AsymmetricCrypto::verify(
            new HiddenString($checksum),
            $publicKey,
            $signature,
            $raw_binary
        );
    }

    /**
     * Get the configuration
     *
     * @param string $header
     * @param string $mode
     * @return Config
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     */
    protected static function getConfig(
        string $header,
        string $mode = 'encrypt'
    ): Config {
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 65) {
            throw new CryptoException\InvalidMessage(
                'Invalid version tag'
            );
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
        throw new CryptoException\InvalidType(
            'Invalid configuration mode'
        );
    }

    /**
     * Get the configuration for encrypt operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigEncrypt(int $major, int $minor): array
    {
        if ($major === 2) {
            switch ($minor) {
                case 1:
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 92,
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 92,
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        // If we reach here, we've got an invalid version tag:
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }

    /**
     * Get the configuration for seal operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigSeal(int $major, int $minor): array
    {
        if ($major === 2) {
            switch ($minor) {
                case 1:
                case 0:
                    return [
                        'SHORTEST_CIPHERTEXT_LENGTH' => 100,
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
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
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }

    /**
     * Get the configuration for encrypt operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigChecksum(int $major, int $minor): array
    {
        if ($major === 2) {
            switch ($minor) {
                case 1:
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => true,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => true,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }

    /**
     * Split a key using HKDF-BLAKE2b
     *
     * @param Key $master
     * @param string $salt
     * @param Config $config
     * @return string[]
     */
    protected static function splitKeys(
        Key $master,
        string $salt = '',
        Config $config = null
    ): array {
        $binary = $master->getRawKeyMaterial();
        return [
            Util::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                $config->HKDF_SBOX,
                $salt
            ),
            Util::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                $config->HKDF_AUTH,
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
     * @param resource $mac (hash context)
     * @param Config $config
     * @return int (number of bytes)
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidKey
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
                ($input->getPos() + $config->BUFFER) > $size
                    ? ($size - $input->getPos())
                    : $config->BUFFER
            );

            $encrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->getRawKeyMaterial()
            );
            \Sodium\crypto_generichash_update($mac, $encrypted);
            $written += $output->writeBytes($encrypted);
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);

        // Check that our input file was not modified before we MAC it
        if (!\hash_equals($input->getHash(), $initHash)) {
            throw new CryptoException\FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
        $written += $output->writeBytes(
            \Sodium\crypto_generichash_final($mac, $config->MAC_SIZE),
            $config->MAC_SIZE
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
     * @param resource $mac (hash context)
     * @param Config $config
     * @param array &$chunk_macs
     * @return bool
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
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
        $cipher_end = $input->getSize() - $config->MAC_SIZE;
        // Begin the streaming decryption
        $input->reset($start);

        while ($input->remainingBytes() > $config->MAC_SIZE) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if (($input->getPos() + $config->BUFFER) > $cipher_end) {
                $read = $input->readBytes(
                    $cipher_end - $input->getPos()
                );
            } else {
                $read = $input->readBytes($config->BUFFER);
            }

            // Version 2+ uses a keyed BLAKE2b hash instead of HMAC
            \Sodium\crypto_generichash_update($mac, $read);
            $calcMAC = Util::safeStrcpy($mac);
            $calc = \Sodium\crypto_generichash_final($calcMAC, $config->MAC_SIZE);

            if (empty($chunk_macs)) {
                // Someone attempted to add a chunk at the end.
                throw new CryptoException\InvalidMessage(
                    'Invalid message authentication code'
                );
            } else {
                $chunkMAC = \array_shift($chunk_macs);
                if (!\hash_equals($chunkMAC, $calc)) {
                    // This chunk was altered after the original MAC was verified
                    throw new CryptoException\InvalidMessage(
                        'Invalid message authentication code'
                    );
                }
            }

            // This is where the decryption actually occurs:
            $decrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->getRawKeyMaterial()
            );
            $output->writeBytes($decrypted);
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);
        return true;
    }

    /**
     * Recalculate and verify the HMAC of the input file
     *
     * @param ReadOnlyFile $input  The file we are verifying
     * @param resource|string $mac (hash context)
     * @param Config $config       Version-specific settings
     * @return array               Hashes of various chunks
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidMessage
     */
    final private static function streamVerify(
        ReadOnlyFile $input,
        $mac,
        Config $config
    ): array {
        $start = $input->getPos();

        // Grab the stored MAC:
        $cipher_end = $input->getSize() - $config->MAC_SIZE;
        $input->reset($cipher_end);
        $stored_mac = $input->readBytes($config->MAC_SIZE);
        $input->reset($start);

        $chunkMACs = [];

        $break = false;
        while (!$break && $input->getPos() < $cipher_end) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if (($input->getPos() + $config->BUFFER) >= $cipher_end) {
                $break = true;
                $read = $input->readBytes($cipher_end - $input->getPos());
            } else {
                $read = $input->readBytes($config->BUFFER);
            }

            /**
             * We're updating our HMAC and nothing else
             */
            \Sodium\crypto_generichash_update($mac, $read);
            // Copy the hash state then store the MAC of this chunk
            $chunkMAC = Util::safeStrcpy($mac);
            $chunkMACs []= \Sodium\crypto_generichash_final(
                $chunkMAC,
                $config->MAC_SIZE
            );
        }

        /**
         * We should now have enough data to generate an identical MAC
         */
        $finalHMAC = \Sodium\crypto_generichash_final(
            $mac,
            $config->MAC_SIZE
        );

        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!\hash_equals($finalHMAC, $stored_mac)) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        $input->reset($start);
        return $chunkMACs;
    }
}
