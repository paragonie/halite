<?php
declare(strict_types = 1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\Halite\{
    Alerts as CryptoException, Config as BaseConfig, Halite, Util
};

/**
 * Class Config
 *
 * Secure encrypted cookies
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Symmetric
 */
final class Config extends BaseConfig
{
    /**
     * Get the configuration
     *
     * @param string $header
     * @param string $mode
     * @return Config
     * @throws CryptoException\InvalidMessage
     */
    public static function getConfig(
        string $header,
        string $mode = 'encrypt'
    ): self {
        if (Util::safeStrlen($header) < Halite::VERSION_TAG_LEN) {
            throw new CryptoException\InvalidMessage(
                'Invalid version tag'
            );
        }
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 66) {
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
        } elseif ($mode === 'auth') {
            return new Config(
                self::getConfigAuth($major, $minor)
            );
        }
        throw new CryptoException\InvalidMessage(
            'Invalid configuration mode: ' . $mode
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
    public static function getConfigEncrypt(int $major, int $minor): array
    {
        if ($major === 2) {
            switch ($minor) {
                case 1:
                case 0:
                    return [
                        'ENCODING'                   => Halite::ENCODE_HEX,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 124,
                        'NONCE_BYTES'                => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN'              => 32,
                        'MAC_ALGO'                   => 'BLAKE2b',
                        'MAC_SIZE'                   => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX,
                        'HKDF_SBOX'                  => 'Halite|EncryptionKey',
                        'HKDF_AUTH'                  => 'AuthenticationKeyFor_|Halite',
                    ];
            }
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'ENCODING'                   => Halite::ENCODE_BASE64URLSAFE,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 124,
                        'NONCE_BYTES'                => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN'              => 32,
                        'MAC_ALGO'                   => 'BLAKE2b',
                        'MAC_SIZE'                   => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX,
                        'HKDF_SBOX'                  => 'Halite|EncryptionKey',
                        'HKDF_AUTH'                  => 'AuthenticationKeyFor_|Halite',
                    ];
            }
        }
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
    public static function getConfigAuth(int $major, int $minor): array
    {
        if ($major === 2) {
            switch ($minor) {
                case 1:
                case 0:
                    return [
                        'HKDF_SALT_LEN'   => 32,
                        'MAC_ALGO'        => 'BLAKE2b',
                        'MAC_SIZE'        => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX'       => 'Halite|EncryptionKey',
                        'HKDF_AUTH'       => 'AuthenticationKeyFor_|Halite',
                    ];
            }
        } elseif ($major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'HKDF_SALT_LEN'   => 32,
                        'MAC_ALGO'        => 'BLAKE2b',
                        'MAC_SIZE'        => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX'       => 'Halite|EncryptionKey',
                        'HKDF_AUTH'       => 'AuthenticationKeyFor_|Halite',
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }
}
