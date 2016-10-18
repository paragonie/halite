<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\Halite\Alerts\{
    InvalidKey,
    InvalidMessage,
    InvalidSignature
};
use ParagonIE\Halite\{
    Halite,
    HiddenString,
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
     * Don't allow this to be instantiated.
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Authenticate a string
     *
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param mixed $encoding
     * @throws InvalidKey
     * @return string
     */
    public static function authenticate(
        string $message,
        AuthenticationKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $config = Config::getConfig(
            Halite::HALITE_VERSION,
            'auth'
        );
        $mac = self::calculateMAC(
            $message,
            $secretKey->getRawKeyMaterial(),
            $config
        );
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return $encoder($mac);
        }
        return $mac;
    }

    /**
     * Decrypt a message using the Halite encryption protocol
     *
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param mixed $encoding
     * @return HiddenString
     * @throws InvalidMessage
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given encoded data:
            try {
                $ciphertext = $decoder($ciphertext);
            } catch (\RangeException $ex) {
                throw new InvalidMessage(
                    'Invalid character encoding'
                );
            }
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
            throw new InvalidMessage(
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
            throw new InvalidMessage(
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
     * (Encrypt then MAC -- xsalsa20 then keyed-Blake2b)
     * You don't need to worry about chosen-ciphertext attacks.
     *
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param mixed $encoding
     * @return string
     */
    public static function encrypt(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $config = Config::getConfig(Halite::HALITE_VERSION, 'encrypt');

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
            return $encoder($message);
        }
        return $message;
    }

    /**
     * Split a key (using HKDF-BLAKE2b instead of HKDF-HMAC-*)
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
     * Unpack a message string into an array (assigned to variables via list()).
     *
     * Should return exactly 6 elements.
     *
     * @param string $ciphertext
     * @return string[]
     * @throws InvalidMessage
     */
    public static function unpackMessageForDecryption(string $ciphertext): array
    {
        $length = CryptoUtil::safeStrlen($ciphertext);

        // Fail fast on invalid messages
        if ($length < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                'Message is too short'
            );
        }

        // The first 4 bytes are reserved for the version size
        $version = CryptoUtil::safeSubstr(
            $ciphertext,
            0,
            Halite::VERSION_TAG_LEN
        );
        $config = Config::getConfig($version, 'encrypt');

        if ($length < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new InvalidMessage(
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
            // $length - 124
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
     * Verify the authenticity of a message, given a shared MAC key
     *
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param string $mac
     * @param mixed $encoding
     * @param Config $config
     * @return bool
     */
    public static function verify(
        string $message,
        AuthenticationKey $secretKey,
        string $mac,
        $encoding = Halite::ENCODE_BASE64URLSAFE,
        Config $config = null
    ): bool {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            $mac = $decoder($mac);
        }
        if ($config === null) {
            // Default to the current version
            $config = Config::getConfig(
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
     * Calculate a MAC. This is used internally.
     *
     * @param string $message
     * @param string $authKey
     * @param Config $config
     * @return string
     * @throws InvalidMessage
     */
    protected static function calculateMAC(
        string $message,
        string $authKey,
        Config $config
    ): string {
        if ($config->MAC_ALGO === 'BLAKE2b') {
            return \Sodium\crypto_generichash(
                $message,
                $authKey,
                $config->MAC_SIZE
            );
        }
        throw new InvalidMessage(
            'Invalid Halite version'
        );
    }

    /**
     * Verify a Message Authentication Code (MAC) of a message, with a shared
     * key.
     *
     * @param string $mac             Message Authentication Code
     * @param string $message         The message to verify
     * @param string $authKey         Authentication key (symmetric)
     * @param Config $config Configuration object
     * @return bool
     * @throws InvalidMessage
     * @throws InvalidSignature
     */
    protected static function verifyMAC(
        string $mac,
        string $message,
        string $authKey,
        Config $config
    ): bool {
        if (CryptoUtil::safeStrlen($mac) !== $config->MAC_SIZE) {
            throw new InvalidSignature(
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
        }
        throw new InvalidMessage(
            'Invalid Halite version'
        );
    }
}
