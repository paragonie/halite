<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\{
    Config,
    Halite,
    Symmetric\Config as SymmetricConfig,
    Util as CryptoUtil
};

abstract class Crypto
{
    /**
     * Authenticate a string
     * 
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param boolean $raw
     * @throws CryptoException\InvalidKey
     * @return string
     */
    public static function authenticate(
        string $message,
        AuthenticationKey $secretKey,
        bool $raw = false
    ): string {
        $config = SymmetricConfig::getConfig(Halite::HALITE_VERSION, 'auth');
        $mac = self::calculateMAC($message, $secretKey->get(), $config);
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
     * @param boolean $raw Don't hex decode the input?
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
        list($version, $config, $salt, $nonce, $xored, $auth) = 
            self::unpackMessageForDecryption($ciphertext);
        
        // Split our keys
        list($eKey, $aKey) = self::splitKeys($secretKey, $salt, $config);
        
        // Check the MAC first
        if (!self::verifyMAC(
            $auth, 
            $version . $salt . $nonce . $xored,
            $aKey
        )) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        
        // Down the road, do whatever logic around $version here, in case we
        // need to upgrade our protocol.
        
        // Add version logic above
        $plaintext = \Sodium\crypto_stream_xor($xored, $nonce, $eKey);
        if ($plaintext === false) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        return $plaintext;
    }
    
    /**
     * Encrypt a message using the Halite encryption protocol
     * (Encrypt then MAC -- Xsalsa20 then HMAC-SHA-512/256)
     * 
     * @param string $plaintext
     * @param EncryptionKey $secretKey
     * @param boolean $raw Don't hex encode the output?
     * @return string
     */
    public static function encrypt(
        string $plaintext,
        EncryptionKey $secretKey,
        bool $raw = false
    ): string {
        $config = SymmetricConfig::getConfig(Halite::HALITE_VERSION, 'encrypt');
        
        // Generate a nonce and HKDF salt:
        $nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_SECRETBOX_NONCEBYTES);
        $salt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);
        
        // Split our keys according to the HKDF salt:
        list($eKey, $aKey) = self::splitKeys($secretKey, $salt, $config);
        
        // Encrypt our message with the encryption key:
        $xored = \Sodium\crypto_stream_xor($plaintext, $nonce, $eKey);
        
        // Calculate an authentication tag:
        $auth = self::calculateMAC(
            Halite::HALITE_VERSION . $salt . $nonce . $xored,
            $aKey
        );
        
        \Sodium\memzero($eKey);
        \Sodium\memzero($aKey);
        if (!$raw) {
            return \Sodium\bin2hex(
                Halite::HALITE_VERSION . $salt . $nonce . $xored . $auth
            );
        }
        return Halite::HALITE_VERSION . $salt . $nonce . $xored . $auth;
    }
    
    /**
     * Split a key using a variant of HKDF that used a keyed BLAKE2b hash rather
     * than an HMAC construct
     * 
     * @param EncryptionKey $master
     * @param string $salt
     * @param Config $config
     * @return array
     */
    public static function splitKeys(
        EncryptionKey $master,
        string $salt = '',
        Config $config = null
    ) {
        $binary = $master->get();
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
     */
    public static function unpackMessageForDecryption(string $ciphertext): array
    {
        $length = CryptoUtil::safeStrlen($ciphertext);
        
        // The first 4 bytes are reserved for the version size
        $version = CryptoUtil::safeSubstr($ciphertext, 0, Halite::VERSION_TAG_LEN);
        $config = SymmetricConfig::getConfig($version, 'encrypt');
        
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
        $xored = CryptoUtil::safeSubstr(
            $ciphertext, 
            // 60:
                Halite::VERSION_TAG_LEN +
                $config->HKDF_SALT_LEN +
                \Sodium\CRYPTO_STREAM_NONCEBYTES,
            // $length - 92:
            $length - (
                Halite::VERSION_TAG_LEN +
                $config->HKDF_SALT_LEN +
                \Sodium\CRYPTO_STREAM_NONCEBYTES +
                \Sodium\CRYPTO_AUTH_BYTES
            )
        );
        
        // $auth is the last 32 bytes
        $auth = CryptoUtil::safeSubstr($ciphertext, $length - \Sodium\CRYPTO_AUTH_BYTES);
        
        // We don't need this anymore.
        \Sodium\memzero($ciphertext);
        return [$version, $config, $salt, $nonce, $xored, $auth];
    }
    
    /**
     * Verify a MAC, given a MAC key
     * 
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param string $mac
     * @param boolean $raw
     * @return boolean
     */
    public static function verify(
        string $message,
        AuthenticationKey $secretKey,
        string $mac,
        bool $raw = false
    ): bool {
        if (!$raw) {
            $mac = \Sodium\hex2bin($mac);
        }
        return self::verifyMAC(
            $mac,
            $message,
            $secretKey->get()
        );
    }
    
    /**
     * Calculate a MAC
     * 
     * @param string $message
     * @param string $authKey
     * @return string
     */
    protected static function calculateMAC(
        string $message,
        string $authKey
    ): string {
        return \Sodium\crypto_auth(
            $message,
            $authKey
        );
    }
    
    /**
     * Verify a MAC
     * 
     * @param string $mac
     * @param string $message
     * @param string $aKey
     * @return bool
     */
    protected static function verifyMAC(
        string $mac,
        string $message,
        string $aKey
    ): bool {
        if (CryptoUtil::safeStrlen($mac) !== \Sodium\CRYPTO_AUTH_BYTES) {
            throw new CryptoException\InvalidSignature(
                'Message Authentication Code is not the correct length; is it encoded?'
            );
        }
        return \Sodium\crypto_auth_verify(
            $mac, 
            $message,
            $aKey
        );
    }
}
