<?php
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Config as BaseConfig;

class Config extends BaseConfig
{
    /**
     * Get the configuration
     * 
     * @param string $header
     * @param string $mode
     * @return \ParagonIE\Halite\Config
     * @throws CryptoException\InvalidMessage
     */
    public static function getConfig($header, $mode = 'encrypt')
    {
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 66) {
            throw new CryptoException\InvalidMessage(
                'Invalid version tag'
            );
        }
        $major = \ord($header[2]);
        $minor = \ord($header[3]);
        if ($mode === 'encrypt') {
            return new BaseConfig(
                self::getConfigEncrypt($major, $minor)
            );
        } elseif ($mode === 'auth') {
            return new BaseConfig(
                self::getConfigAuth($major, $minor)
            );
        }
        throw new CryptoException\InvalidMessage(
            'Invalid configuration mode: '.$mode
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
    public static function getConfigEncrypt($major, $minor)
    {
        if ($major === 0) {
            switch ($minor) {
                case 1:
                case 6:
                case 7:
                    return [
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
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
     * Get the configuration for seal operations
     * 
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    public static function getConfigAuth($major, $minor)
    {
        if ($major === 0) {
            switch ($minor) {
                case 1:
                case 6:
                case 7:
                    return [
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
}
