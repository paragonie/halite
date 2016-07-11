<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\Halite\{
    Alerts as CryptoException,
    Config,
    Halite,
    Symmetric\Config as SymmetricConfig,
    Util as CryptoUtil
};

/**
 * Class Crypto
 *
 * Encapsulates symmetric-key cryptography
 *
 * @package ParagonIE\Halite\Symmetric
 */
abstract class Crypto
{
    /**
     * Authenticate a string
     * 
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param bool $raw
     * @throws CryptoException\InvalidKey
     * @return string
     */
    public static function authenticate(
        string $message,
        AuthenticationKey $secretKey,
        bool $raw = false
    ): string {
        $config = SymmetricConfig::getConfig(
            Halite::HALITE_VERSION,
            'auth'
        );
        $mac = self::calculateMAC(
            $message,
            $secretKey->getRawKeyMaterial(),
            $config
        );
        if ($raw) {
            return $mac;
        }
        return \Sodium\bin2hex($mac);
    }
    
    /**
     * Decrypt a message using the Halite encryption protocol
     * 
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param bool $raw Don't hex decode the input?
     * @return string
     * @throws CryptoException\InvalidMessage
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        bool $raw = false
    ): string {
        if (!$raw) {
            // We were given hex data:
            $ciphertext = \Sodium\hex2bin($ciphertext);
        }
        list($version, $config, $salt, $nonce, $encrypted, $auth) =
            self::unpackMessageForDecryption($ciphertext);
        
        // Split our keys
        list($encKey, $authKey) = self::splitKeys($secretKey, $salt, $config);
        
        // Check the MAC first
        if (!self::verifyMAC(
            $auth,
            $version . $salt . $nonce . $encrypted,
            $authKey,
            $config
        )) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        \Sodium\memzero($salt);
        \Sodium\memzero($authKey);

        // crypto_stream_xor() can be used to encrypt and decrypt
        $plaintext = \Sodium\crypto_stream_xor($encrypted, $nonce, $encKey);
        if ($plaintext === false) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        \Sodium\memzero($encrypted);
        \Sodium\memzero($nonce);
        \Sodium\memzero($encKey);
        return $plaintext;
    }
    
    /**
     * Encrypt a message using the Halite encryption protocol
     *
     * Version 2:
     * (Encrypt then MAC -- xsalsa20 then keyed-Blake2b)
     *
     * Version 1:
     * (Encrypt then MAC -- xsalsa20 then HMAC-SHA-512/256)
     * 
     * @param string $plaintext
     * @param EncryptionKey $secretKey
     * @param bool $raw Don't hex encode the output?
     * @return string
     */
    public static function encrypt(
        string $plaintext,
        EncryptionKey $secretKey,
        bool $raw = false
    ): string {
        $config = SymmetricConfig::getConfig(Halite::HALITE_VERSION, 'encrypt');
        
        // Generate a nonce and HKDF salt:
        $nonce = \Sodium\randombytes_buf(
            \Sodium\CRYPTO_SECRETBOX_NONCEBYTES
        );
        $salt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);
        
        // Split our keys according to the HKDF salt:
        list($encKey, $authKey) = self::splitKeys($secretKey, $salt, $config);
        
        // Encrypt our message with the encryption key:
        $encrypted = \Sodium\crypto_stream_xor($plaintext, $nonce, $encKey);
        \Sodium\memzero($encKey);
        
        // Calculate an authentication tag:
        $auth = self::calculateMAC(
            Halite::HALITE_VERSION . $salt . $nonce . $encrypted,
            $authKey,
            $config
        );
        \Sodium\memzero($authKey);

        $message = Halite::HALITE_VERSION . $salt . $nonce . $encrypted . $auth;

        // Wipe every superfluous piece of data from memory
        \Sodium\memzero($nonce);
        \Sodium\memzero($salt);
        \Sodium\memzero($encrypted);
        \Sodium\memzero($auth);

        if (!$raw) {
            return \Sodium\bin2hex($message);
        }
        return $message;
    }
    
    /**
     * Split a key using a variant of HKDF that used a keyed BLAKE2b hash rather
     * than an HMAC construct
     * 
     * @param EncryptionKey $master
     * @param string $salt
     * @param Config $config
     * @return string[]
     */
    public static function splitKeys(
        EncryptionKey $master,
        string $salt = '',
        Config $config = null
    ): array {
        $binary = $master->getRawKeyMaterial();
        return [
            CryptoUtil::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                $config->HKDF_SBOX,
                $salt
            ),
            CryptoUtil::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                $config->HKDF_AUTH, 
                $salt
            )
        ];
    }
    
    /**
     * Unpack a message string into an array.
     * 
     * @param string $ciphertext
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    public static function unpackMessageForDecryption(string $ciphertext): array
    {
        $length = CryptoUtil::safeStrlen($ciphertext);

        // Fail fast on invalid messages
        if ($length < Halite::VERSION_TAG_LEN) {
            throw new CryptoException\InvalidMessage(
                'Message is too short'
            );
        }
        
        // The first 4 bytes are reserved for the version size
        $version = CryptoUtil::safeSubstr($ciphertext, 0, Halite::VERSION_TAG_LEN);
        $config = SymmetricConfig::getConfig($version, 'encrypt');

        if ($length < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new CryptoException\InvalidMessage(
                'Message is too short'
            );
        }
        
        // The HKDF is used for key splitting
        $salt = CryptoUtil::safeSubstr(
            $ciphertext,
            Halite::VERSION_TAG_LEN,
            $config->HKDF_SALT_LEN
        );
        
        // This is the nonce (we authenticated it):
        $nonce = CryptoUtil::safeSubstr(
            $ciphertext, 
            // 36:
            Halite::VERSION_TAG_LEN + $config->HKDF_SALT_LEN,
            // 24:
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        // This is the crypto_stream_xor()ed ciphertext
        $encrypted = CryptoUtil::safeSubstr(
            $ciphertext, 
            // 60:
                Halite::VERSION_TAG_LEN +
                $config->HKDF_SALT_LEN +
                \Sodium\CRYPTO_STREAM_NONCEBYTES,
            // v1: $length - 92, v2: $length - 124
            $length - (
                Halite::VERSION_TAG_LEN +
                $config->HKDF_SALT_LEN +
                \Sodium\CRYPTO_STREAM_NONCEBYTES +
                $config->MAC_SIZE
            )
        );
        
        // $auth is the last 32 bytes
        $auth = CryptoUtil::safeSubstr(
            $ciphertext,
            $length - $config->MAC_SIZE
        );
        
        // We don't need this anymore.
        \Sodium\memzero($ciphertext);
        return [$version, $config, $salt, $nonce, $encrypted, $auth];
    }
    
    /**
     * Verify a MAC, given a MAC key
     * 
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param string $mac
     * @param bool $raw
     * @param SymmetricConfig $config
     * @return bool
     */
    public static function verify(
        string $message,
        AuthenticationKey $secretKey,
        string $mac,
        bool $raw = false,
        SymmetricConfig $config = null
    ): bool {
        if (!$raw) {
            $mac = \Sodium\hex2bin($mac);
        }
        if ($config === null) {
            // Default to the current version
            $config = SymmetricConfig::getConfig(
                Halite::HALITE_VERSION,
                'auth'
            );
        }
        return self::verifyMAC(
            $mac,
            $message,
            $secretKey->getRawKeyMaterial(),
            $config
        );
    }
    
    /**
     * Calculate a MAC
     * 
     * @param string $message
     * @param string $authKey
     * @param SymmetricConfig $config
     * @return string
     * @throws CryptoException\InvalidMessage
     */
    protected static function calculateMAC(
        string $message,
        string $authKey,
        SymmetricConfig $config
    ): string {
        if ($config->MAC_ALGO === 'BLAKE2b') {
            return \Sodium\crypto_generichash(
                $message,
                $authKey,
                $config->MAC_SIZE
            );
        } elseif ($config->MAC_ALGO === 'HMAC-SHA512/256') {
            return \Sodium\crypto_auth(
                $message,
                $authKey
            );
        }
        throw new CryptoException\InvalidMessage(
            'Invalid Halite version'
        );
    }
    
    /**
     * Verify a MAC
     * 
     * @param string $mac             Message Authentication Code
     * @param string $message         The message to verify
     * @param string $authKey         Authentication key (symmetric)
     * @param SymmetricConfig $config Configuration object
     * @return bool
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidSignature
     */
    protected static function verifyMAC(
        string $mac,
        string $message,
        string $authKey,
        SymmetricConfig $config
    ): bool {
        if (CryptoUtil::safeStrlen($mac) !== $config->MAC_SIZE) {
            throw new CryptoException\InvalidSignature(
                'Argument 1: Message Authentication Code is not the correct length; is it encoded?'
            );
        }
        if ($config->MAC_ALGO === 'BLAKE2b') {
            $calc = \Sodium\crypto_generichash(
                $message,
                $authKey,
                $config->MAC_SIZE
            );
            $res = \hash_equals($mac, $calc);
            \Sodium\memzero($calc);
            return $res;
        } elseif ($config->MAC_ALGO === 'HMAC-SHA512/256') {
            return \Sodium\crypto_auth_verify(
                $mac,
                $message,
                $authKey
            );
        }
        throw new CryptoException\InvalidMessage(
            'Invalid Halite version'
        );
    }
}
