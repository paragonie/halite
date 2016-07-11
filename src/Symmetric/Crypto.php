<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\Halite\{
    Alerts as CryptoException,
    Config,
    Halite,
    HiddenString,
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
final class Crypto
{
    /**
     * Authenticate a string
     * 
     * @param HiddenString $message
     * @param AuthenticationKey $secretKey
     * @param mixed $encoding
     * @throws CryptoException\InvalidKey
     * @return HiddenString
     */
    public static function authenticate(
        HiddenString $message,
        AuthenticationKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $config = SymmetricConfig::getConfig(
            Halite::HALITE_VERSION,
            'auth'
        );
        $mac = self::calculateMAC(
            $message->getString(),
            $secretKey->getRawKeyMaterial(),
            $config
        );
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return new HiddenString($encoder($mac));
        }
        return new HiddenString($mac);
    }
    
    /**
     * Decrypt a message using the Halite encryption protocol
     * 
     * @param HiddenString $ciphertext
     * @param EncryptionKey $secretKey
     * @param mixed $encoding
     * @return HiddenString
     * @throws CryptoException\InvalidMessage
     */
    public static function decrypt(
        HiddenString $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            try {
                $ciphertext = $decoder($ciphertext->getString());
            } catch (\RangeException $ex) {
                throw new CryptoException\InvalidMessage(
                    'Invalid character encoding'
                );
            }
        } else {
            $ciphertext = $ciphertext->getString();
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
        $plaintext = \Sodium\crypto_stream_xor(
            $encrypted,
            $nonce,
            $encKey
        );
        if ($plaintext === false) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        \Sodium\memzero($encrypted);
        \Sodium\memzero($nonce);
        \Sodium\memzero($encKey);
        return new HiddenString($plaintext);
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
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param mixed $encoding
     * @return HiddenString
     */
    public static function encrypt(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $config = SymmetricConfig::getConfig(Halite::HALITE_VERSION, 'encrypt');
        
        // Generate a nonce and HKDF salt:
        $nonce = \Sodium\randombytes_buf(
            \Sodium\CRYPTO_SECRETBOX_NONCEBYTES
        );
        $salt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);
        
        // Split our keys according to the HKDF salt:
        list($encKey, $authKey) = self::splitKeys($secretKey, $salt, $config);
        
        // Encrypt our message with the encryption key:
        $encrypted = \Sodium\crypto_stream_xor(
            $plaintext->getString(),
            $nonce,
            $encKey
        );
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

        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return new HiddenString($encoder($message));
        }
        return new HiddenString($message);
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
     * @param HiddenString $message
     * @param AuthenticationKey $secretKey
     * @param HiddenString $mac
     * @param mixed $encoding
     * @param SymmetricConfig $config
     * @return bool
     */
    public static function verify(
        HiddenString $message,
        AuthenticationKey $secretKey,
        HiddenString $mac,
        $encoding = Halite::ENCODE_BASE64URLSAFE,
        SymmetricConfig $config = null
    ): bool {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            $mac = $decoder($mac->getString());
        } else {
            $mac = $mac->getString();
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
            $message->getString(),
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
