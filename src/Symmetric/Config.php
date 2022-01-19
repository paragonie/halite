<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\{
    Config as BaseConfig,
    Halite,
    Util
};
use const
    SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
    SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
    SODIUM_CRYPTO_STREAM_NONCEBYTES;

/**
 * Class Config
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Symmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class Config extends BaseConfig
{
    /**
     * Get the configuration
     *
     * @param string $header
     * @param string $mode
     *
     * @return self
     *
     * @throws InvalidMessage
     */
    public static function getConfig(
        string $header,
        string $mode = 'encrypt'
    ): self {
        if (Binary::safeStrlen($header) < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                'Invalid version tag'
            );
        }
        if (Util::chrToInt($header[0]) !== 49 || Util::chrToInt($header[1]) !== 66) {
            throw new InvalidMessage(
                'Invalid version tag'
            );
        }
        $major = Util::chrToInt($header[2]);
        $minor = Util::chrToInt($header[3]);
        if ($mode === 'encrypt') {
            return new Config(
                self::getConfigEncrypt($major, $minor)
            );
        } elseif ($mode === 'auth') {
            return new Config(
                self::getConfigAuth($major, $minor)
            );
        }
        throw new InvalidMessage(
            'Invalid configuration mode: '.$mode
        );
    }
    
    /**
     * Get the configuration for encrypt operations
     * 
     * @param int $major
     * @param int $minor
     *
     * @return array
     *
     * @throws InvalidMessage
     */
    public static function getConfigEncrypt(int $major, int $minor): array
    {
        if ($major === 5) {
            switch ($minor) {
                case 0:
                    return [
                        'ENCODING' => Halite::ENCODE_BASE64URLSAFE,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 124,
                        'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'ENC_ALGO' => 'XChaCha20',
                        'USE_PAE' => true,
                        'MAC_ALGO' => 'BLAKE2b',
                        'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
                        'HKDF_USE_INFO' => true,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        if ($major === 4 || $major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'ENCODING' => Halite::ENCODE_BASE64URLSAFE,
                        'SHORTEST_CIPHERTEXT_LENGTH' => 124,
                        'NONCE_BYTES' => SODIUM_CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'ENC_ALGO' => 'XSalsa20',
                        'USE_PAE' => false,
                        'MAC_ALGO' => 'BLAKE2b',
                        'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
                        'HKDF_USE_INFO' => false,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        throw new InvalidMessage(
            'Invalid version tag'
        );
    }
    
    /**
     * Get the configuration for seal operations
     * 
     * @param int $major
     * @param int $minor
     *
     * @return array
     *
     * @throws InvalidMessage
     */
    public static function getConfigAuth(int $major, int $minor): array
    {
        if ($major === 4 || $major === 5) {
            switch ($minor) {
                case 0:
                    return [
                        'USE_PAE' => $major >= 5,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_ALGO' => 'BLAKE2b',
                        'MAC_SIZE' => SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
                        'PUBLICKEY_BYTES' => SODIUM_CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_USE_INFO' => $major > 4,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        throw new InvalidMessage(
            'Invalid version tag'
        );
    }
}
