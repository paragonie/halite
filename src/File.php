<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\{
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

final class File
{
    /**
     * Lazy fallthrough method for checksumFile() and checksumResource()
     *
     * @param string|resource $filepath
     * @param Key $key (optional; expects SignaturePublicKey or AuthenticationKey)
     * @param bool $raw
     * @return string
     * @throws CryptoException\InvalidType
     */
    public static function checksum(
        $filepath,
        Key $key = null,
        $raw = false
    ): string {
        if (\is_resource($filepath) || \is_string($filepath)) {
            $readOnly = new ReadOnlyFile($filepath);
            $csum = self::checksumData(
                $readOnly,
                $key,
                $raw
            );
            $readOnly->close();
            return $csum;
        }
        throw new CryptoException\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }

    /**
     * Lazy fallthrough method for encryptFile() and encryptResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     * @return int (number of bytes written)
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
     * Lazy fallthrough method for decryptFile() and decryptResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     * @return bool
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
     * Lazy fallthrough method for sealFile() and sealResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionPublicKey $publickey
     * @return int Number of bytes written
     * @throws Alerts\InvalidType
     */
    public static function seal(
        $input,
        $output,
        EncryptionPublicKey $publickey
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
                $publickey
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
     * Lazy fallthrough method for sealFile() and sealResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionSecretKey $secretkey
     * @return bool TRUE on success
     * @throws CryptoException\InvalidType
     */
    public static function unseal(
        $input,
        $output,
        EncryptionSecretKey $secretkey
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
                    $secretkey
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
     * Lazy fallthrough method for signFile() and signResource()
     *
     * @param string|resource $filename
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary
     * @return string
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     */
    public static function sign(
        $filename,
        SignatureSecretKey $secretkey,
        bool $raw_binary = false
    ): string {
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            $readOnly = new ReadOnlyFile($filename);
            $signature = self::signData(
                $readOnly,
                $secretkey,
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
     * Lazy fallthrough method for verifyFile() and verifyResource()
     *
     * @param string|resource $filename
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary
     *
     * @return bool
     * @throws CryptoException\InvalidType
     */
    public static function verify(
        $filename,
        SignaturePublicKey $publickey,
        string $signature,
        bool $raw_binary = false
    ): bool {
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            $readOnly = new ReadOnlyFile($filename);
            $verified = self::verifyData(
                $readOnly,
                $publickey,
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
     * Calculate the BLAKE2b checksum of an entire stream
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
     * Encrypt a (file handle)
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
        $firstnonce = \Sodium\randombytes_buf($config->NONCE_BYTES);
        $hkdfsalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);

        // Let's split our key
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);

        // Write the header
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $firstnonce,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        $output->writeBytes(
            $hkdfsalt,
            $config->HKDF_SALT_LEN
        );

        if ($config->USE_BLAKE2B) {
            // VERSION 2+
            $mac = \Sodium\crypto_generichash_init($authKey);
            \Sodium\crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            \Sodium\crypto_generichash_update($mac, $firstnonce);
            \Sodium\crypto_generichash_update($mac, $hkdfsalt);
        } else {
            // VERSION 1
            $mac = \hash_init('sha256', HASH_HMAC, $authKey);
            // We no longer need $authKey after we set up the hash context
            unset($authKey);

            \hash_update($mac, Halite::HALITE_VERSION_FILE);
            \hash_update($mac, $firstnonce);
            \hash_update($mac, $hkdfsalt);
        }
        \Sodium\memzero($authKey);

        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $firstnonce,
            $mac,
            $config
        );
    }

    /**
     * Decrypt a (file handle)
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
        $input->reset(0);
        if ($input->getSize() < Halite::VERSION_TAG_LEN) {
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }
        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);

        // Load the config
        $config = self::getConfig($header, 'encrypt');

        if ($input->getSize() < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new CryptoException\InvalidMessage(
                "Input file is too small to have been encrypted by Halite."
            );
        }

        // Let's grab the first nonce and salt
        $firstnonce = $input->readBytes($config->NONCE_BYTES);
        $hkdfsalt = $input->readBytes($config->HKDF_SALT_LEN);

        // Split our keys, begin the HMAC instance
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);

        if ($config->USE_BLAKE2B) {
            // VERSION 2+
            $mac = \Sodium\crypto_generichash_init($authKey);
            \Sodium\crypto_generichash_update($mac, $header);
            \Sodium\crypto_generichash_update($mac, $firstnonce);
            \Sodium\crypto_generichash_update($mac, $hkdfsalt);

            $old_macs = self::streamVerify($input, ''.$mac, $config);
        } else {
            // VERSION 1
            $mac = \hash_init('sha256', HASH_HMAC, $authKey);
            \hash_update($mac, $header);
            \hash_update($mac, $firstnonce);
            \hash_update($mac, $hkdfsalt);

            // This will throw an exception if it fails.
            $old_macs = self::streamVerify($input, \hash_copy($mac), $config);
        }
        \Sodium\memzero($authKey);

        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $firstnonce,
            $mac,
            $config,
            $old_macs
        );

        unset($encKey);
        unset($authKey);
        unset($firstnonce);
        unset($mac);
        unset($config);
        unset($old_macs);
        return $ret;
    }

    /**
     * Seal a (file handle)
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionPublicKey $publickey
     * @return int
     */
    protected static function sealData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionPublicKey $publickey
    ): int {
        // Generate a new keypair for this encryption
        $eph_kp = KeyFactory::generateEncryptionKeyPair();
        $eph_secret = $eph_kp->getSecretKey();
        $eph_public = $eph_kp->getPublicKey();
        unset($eph_kp);

        // Calculate the shared secret key
        $key = AsymmetricCrypto::getSharedSecret($eph_secret, $publickey, true);

        // Destroy the secre tkey after we have the shared secret
        unset($eph_secret);
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'seal');

        // Generate a nonce as per crypto_box_seal
        $nonce = \Sodium\crypto_generichash(
            $eph_public->getRawKeyMaterial().$publickey->getRawKeyMaterial(),
            '',
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );

        // Generate a random HKDF salt
        $hkdfsalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);

        // Split the keys
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);

        // We no longer need the original key after we split it
        unset($key);

        // Write the header:
        $output->writeBytes(
            Halite::HALITE_VERSION_FILE,
            Halite::VERSION_TAG_LEN
        );
        $output->writeBytes(
            $eph_public->getRawKeyMaterial(),
            \Sodium\CRYPTO_BOX_PUBLICKEYBYTES
        );
        $output->writeBytes(
            $hkdfsalt,
            $config->HKDF_SALT_LEN
        );

        if ($config->USE_BLAKE2B) {
            // VERSION 2+
            $mac = \Sodium\crypto_generichash_init($authKey);
            // We no longer need $authKey after we set up the hash context
            \Sodium\memzero($authKey);

            \Sodium\crypto_generichash_update($mac, Halite::HALITE_VERSION_FILE);
            \Sodium\crypto_generichash_update($mac, $eph_public->getRawKeyMaterial());
            \Sodium\crypto_generichash_update($mac, $hkdfsalt);
        } else {
            // VERSION 1
            $mac = \hash_init('sha256', HASH_HMAC, $authKey);
            // We no longer need $authKey after we set up the hash context
            \Sodium\memzero($authKey);

            \hash_update($mac, Halite::HALITE_VERSION_FILE);
            \hash_update($mac, $eph_public->getRawKeyMaterial());
            \hash_update($mac, $hkdfsalt);
        }

        unset($eph_public);

        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $nonce,
            $mac,
            $config
        );
    }

    /**
     * Unseal a (file handle)
     *
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionSecretKey $secretkey
     *
     * @return bool
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidMessage
     */
    protected static function unsealData(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionSecretKey $secretkey
    ): bool {
        $secret_key = $secretkey->getRawKeyMaterial();
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);

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
        $eph_public = $input->readBytes($config->PUBLICKEY_BYTES);
        $hkdfsalt = $input->readBytes($config->HKDF_SALT_LEN);

        // Generate the same nonce, as per sealData()
        $nonce = \Sodium\crypto_generichash(
            $eph_public . $public_key,
            '',
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );

        $ephemeral = new EncryptionPublicKey($eph_public);

        $key = AsymmetricCrypto::getSharedSecret(
            $secretkey,
            $ephemeral,
            true
        );
        unset($ephemeral);

        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);
        // We no longer need the original key after we split it
        unset($key);

        if ($config->USE_BLAKE2B) {
            $mac = \Sodium\crypto_generichash_init($authKey);
            \Sodium\crypto_generichash_update($mac, $header);
            \Sodium\crypto_generichash_update($mac, $eph_public);
            \Sodium\crypto_generichash_update($mac, $hkdfsalt);

            $old_macs = self::streamVerify($input, ''.$mac, $config);
        } else {
            $mac = \hash_init('sha256', HASH_HMAC, $authKey);
            \hash_update($mac, $header);
            \hash_update($mac, $eph_public);
            \hash_update($mac, $hkdfsalt);

            // This will throw an exception if it fails.
            $old_macs = self::streamVerify($input, \hash_copy($mac), $config);
        }

        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $nonce,
            $mac,
            $config,
            $old_macs
        );

        unset($encKey);
        unset($authKey);
        unset($nonce);
        unset($mac);
        unset($config);
        unset($old_macs);
        return $ret;
    }

    /**
     * Sign the contents of a file
     *
     * @param ReadOnlyFile $input
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary Don't hex encode?
     * @return string
     */
    protected static function signData(
        ReadOnlyFile $input,
        SignatureSecretKey $secretkey,
        bool $raw_binary = false
    ): string {
        $csum = self::checksumData(
            $input,
            $secretkey->derivePublicKey(),
            true
        );
        return AsymmetricCrypto::sign($csum, $secretkey, $raw_binary);
    }

    /**
     * Verify the contents of a file
     *
     * @param $input (file handle)
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary Don't hex encode?
     *
     * @return bool
     */
    protected static function verifyData(
        ReadOnlyFile $input,
        SignaturePublicKey $publickey,
        string $signature,
        bool $raw_binary = false
    ): bool {
        $csum = self::checksumData($input, $publickey, true);
        return AsymmetricCrypto::verify(
            $csum,
            $publickey,
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
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'USE_BLAKE2B' => false,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 92,
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'USE_BLAKE2B' => true,
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
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'USE_BLAKE2B' => false,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 100,
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'USE_BLAKE2B' => true,
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
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => false,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        } elseif ($major === 2) {
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
     * Split a key using HKDF
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
        $mac,
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
            if ($config->USE_BLAKE2B) {
                // VERSION 2+
                \Sodium\crypto_generichash_update($mac, $encrypted);
            } else {
                // VERSION 1
                \hash_update($mac, $encrypted);
            }
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
        if ($config->USE_BLAKE2B) {
            // VERSION 2+
            $written += $output->writeBytes(
                \Sodium\crypto_generichash_final($mac, $config->MAC_SIZE),
                $config->MAC_SIZE
            );
        } else {
            // VERSION 1
            $written += $output->writeBytes(
                \hash_final($mac, true)
            );
        }
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
        $mac,
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

            if ($config->USE_BLAKE2B) {
                \Sodium\crypto_generichash_update($mac, $read);
                $calcMAC = ''.$mac;
                $calc = \Sodium\crypto_generichash_final($calcMAC, $config->MAC_SIZE);
            } else {
                \hash_update($mac, $read);
                $calcMAC = \hash_copy($mac);
                if ($calcMAC === false) {
                    throw new CryptoException\CannotPerformOperation(
                        'An unknown error has occurred'
                    );
                }
                $calc = \hash_final($calcMAC, true);
            }

            if (empty($chunk_macs)) {
                throw new CryptoException\InvalidMessage(
                    'Invalid message authentication code'
                );
            } else {
                $chkmac = \array_shift($chunk_macs);
                if (!\hash_equals($chkmac, $calc)) {
                    throw new CryptoException\InvalidMessage(
                        'Invalid message authentication code'
                    );
                }
            }

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
     * @param ReadOnlyFile $input
     * @param resource|string $mac (hash context)
     * @param Config $config
     *
     * @return array Hashes of various chunks
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidMessage
     */
    final private static function streamVerify(
        ReadOnlyFile $input,
        $mac,
        Config $config
    ): array {
        $start = $input->getPos();

        $cipher_end = $input->getSize() - $config->MAC_SIZE;
        $input->reset($cipher_end);
        $stored_mac = $input->readBytes($config->MAC_SIZE);
        $input->reset($start);

        $chunk_macs = [];

        $break = false;
        while (!$break && $input->getPos() < $cipher_end) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($input->getPos() + $config->BUFFER >= $cipher_end) {
                $break = true;
                $read = $input->readBytes($cipher_end - $input->getPos());
            } else {
                $read = $input->readBytes($config->BUFFER);
            }

            /**
             * We're updating our HMAC and nothing else
             */
            if ($config->USE_BLAKE2B) {
                // VERSION 2+
                \Sodium\crypto_generichash_update($mac, $read);
                $chunkMAC = '' . $mac;
                $chunk_macs []= \Sodium\crypto_generichash_final($chunkMAC, $config->MAC_SIZE);
            } else {
                // VERSION 1
                \hash_update($mac, $read);
                /**
                 * Store a MAC of each chunk
                 */
                $chunkMAC = \hash_copy($mac);
                if ($chunkMAC === false) {
                    throw new CryptoException\CannotPerformOperation(
                        'An unknown error has occurred'
                    );
                }
                $chunk_macs []= \hash_final($chunkMAC, true);
            }
        }

        /**
         * We should now have enough data to generate an identical HMAC
         */
        if ($config->USE_BLAKE2B) {
            // VERSION 2+
            $finalHMAC = \Sodium\crypto_generichash_final($mac, $config->MAC_SIZE);
        } else {
            // VERSION 1
            $finalHMAC = \hash_final($mac, true);
        }

        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!\hash_equals($finalHMAC, $stored_mac)) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        $input->reset($start);
        return $chunk_macs;
    }
}
