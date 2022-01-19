<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use Error;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength,
    InvalidMessage,
    InvalidSignature,
    InvalidType
};
use ParagonIE\Halite\{
    Config as BaseConfig, 
    Halite, 
    Symmetric\Config as SymmetricConfig,
    Util
};
use ParagonIE\HiddenString\HiddenString;
use RangeException;
use SodiumException;
use Throwable;
use TypeError;
use const
    SODIUM_CRYPTO_AUTH_KEYBYTES,
    SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
    SODIUM_CRYPTO_STREAM_NONCEBYTES;
use function
    hash_equals,
    is_callable,
    is_null,
    random_bytes,
    sodium_crypto_generichash,
    sodium_crypto_stream_xchacha20_xor,
    sodium_crypto_stream_xor,
    str_repeat;

/**
 * Class Crypto
 *
 * Encapsulates symmetric-key cryptography
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
final class Crypto
{
    /**
     * Don't allow this to be instantiated.
     *
     * @throws Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new Error('Do not instantiate');
    }

    /**
     * Authenticate a string
     *
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param string|bool $encoding
     *
     * @return string
     *
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function authenticate(
        string $message,
        AuthenticationKey $secretKey,
        bool|string $encoding = Halite::ENCODE_BASE64URLSAFE
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
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return (string) $encoder($mac);
        }
        return $mac;
    }

    /**
     * Decrypt a message using the Halite encryption protocol
     *
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param string|bool $encoding
     *
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        bool|string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return self::decryptWithAD(
            $ciphertext,
            $secretKey,
            '',
            $encoding
        );
    }

    /**
     * Decrypt a message using the Halite encryption protocol
     *
     * Verifies the MAC before decryption
     * - Halite 5+ verifies the BLAKE2b-MAC before decrypting with XChaCha20
     * - Halite 4 and below verifies the BLAKE2b-MAC before decrypting with XSalsa20
     *
     * You don't need to worry about chosen-ciphertext attacks.
     * You don't need to worry about Invisible Salamanders.
     * You don't need to worry about timing attacks on MAC validation.
     *
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param string $additionalData
     * @param string|bool $encoding
     *
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decryptWithAD(
        string $ciphertext,
        EncryptionKey $secretKey,
        string $additionalData = '',
        bool|string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $decoder = Halite::chooseEncoder($encoding, true);
        if (is_callable($decoder)) {
            // We were given encoded data:
            // @codeCoverageIgnoreStart
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (RangeException $ex) {
                throw new InvalidMessage(
                    'Invalid character encoding'
                );
            }
            // @codeCoverageIgnoreEnd
        }
        /**
         * @var string $version
         * @var Config $config
         * @var string $salt
         * @var string $nonce
         * @var string $encrypted
         * @var string $auth
         */
        [
            $version,
            $config,
            $salt,
            $nonce,
            $encrypted,
            $auth
        ] = self::unpackMessageForDecryption($ciphertext);

        /* Split our key into two keys: One for encryption, the other for
           authentication. By using separate keys, we can reasonably dismiss
           likely cross-protocol attacks.

           This uses salted HKDF to split the keys, which is why we need the
           salt in the first place. */
        /**
         * @var array<int, string> $split
         * @var string $encKey
         * @var string $authKey
         */
        $split = Util::splitKeys($secretKey, $salt, $config);
        $encKey = $split[0];
        $authKey = $split[1];

        // Check the MAC first
        if ($config->USE_PAE) {
            $verified = self::verifyMAC(
                $auth,
                Util::PAE($version, $salt, $nonce, $additionalData, $encrypted),
                $authKey,
                $config
            );
        } else {
            $verified = self::verifyMAC(
            // @codeCoverageIgnoreStart
                $auth,
                $version .
                    $salt .
                    $nonce .
                    $additionalData .
                    $encrypted,
                // @codeCoverageIgnoreEnd
                $authKey,
                $config
            );
        }

        if (!$verified) {
            throw new InvalidMessage(
                'Invalid message authentication code'
            );
        }
        Util::memzero($salt);
        Util::memzero($authKey);

        // crypto_stream_xor() can be used to encrypt and decrypt
        if ($config->ENC_ALGO === 'XChaCha20') {
            $plaintext = sodium_crypto_stream_xchacha20_xor($encrypted, $nonce, $encKey);
        } else {
            $plaintext = sodium_crypto_stream_xor($encrypted, $nonce, $encKey);
        }
        Util::memzero($encrypted);
        Util::memzero($nonce);
        Util::memzero($encKey);
        return new HiddenString($plaintext);
    }

    /**
     * Encrypt a message using the Halite encryption protocol
     *
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param string|bool $encoding
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        bool|string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return self::encryptWithAD(
            $plaintext,
            $secretKey,
            '',
            $encoding
        );
    }

    /**
     * Encrypt a message using the Halite encryption protocol
     *
     * Encrypt then MAC.
     * - Halite 5+ uses XChaCha20 then BLAKE2b-MAC
     * - Halite 4 and below use XSalsa20 then BLAKE2b-MAC
     *
     * You don't need to worry about chosen-ciphertext attacks.
     * You don't need to worry about Invisible Salamanders.
     *
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param string $additionalData
     * @param bool|string $encoding
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encryptWithAD(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        string $additionalData = '',
        bool|string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $config = SymmetricConfig::getConfig(Halite::HALITE_VERSION, 'encrypt');

        // Generate a nonce and HKDF salt:
        // @codeCoverageIgnoreStart
        try {
            $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $salt = random_bytes((int) $config->HKDF_SALT_LEN);
        } catch (Throwable $ex) {
            throw new CannotPerformOperation($ex->getMessage());
        }
        // @codeCoverageIgnoreEnd

        /* Split our key into two keys: One for encryption, the other for
           authentication. By using separate keys, we can reasonably dismiss
           likely cross-protocol attacks.

           This uses salted HKDF to split the keys, which is why we need the
           salt in the first place. */
        [$encKey, $authKey] = Util::splitKeys($secretKey, $salt, $config);

        // Encrypt our message with the encryption key:

        if ($config->ENC_ALGO === 'XChaCha20') {
            $encrypted = sodium_crypto_stream_xchacha20_xor(
                $plaintext->getString(),
                $nonce,
                $encKey
            );
        } else {
            $encrypted = sodium_crypto_stream_xor(
                $plaintext->getString(),
                $nonce,
                $encKey
            );
        }
        Util::memzero($encKey);

        // Calculate an authentication tag:
        if ($config->USE_PAE) {
            $auth = self::calculateMAC(
                Util::PAE(
                    Halite::HALITE_VERSION,
                    $salt,
                    $nonce,
                    $additionalData,
                    $encrypted
                ),
                $authKey,
                $config
            );
        } else {
            $auth = self::calculateMAC(
                Halite::HALITE_VERSION . $salt . $nonce . $additionalData . $encrypted,
                $authKey,
                $config
            );
        }
        Util::memzero($authKey);

        $message = Halite::HALITE_VERSION . $salt . $nonce . $encrypted . $auth;

        // Wipe every superfluous piece of data from memory
        Util::memzero($nonce);
        Util::memzero($salt);
        Util::memzero($encrypted);
        Util::memzero($auth);

        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return (string) $encoder($message);
        }
        return $message;
    }

    /**
     * Unpack a message string into an array (assigned to variables via list()).
     *
     * Should return exactly 6 elements.
     *
     * @param string $ciphertext
     *
     * @return array<int, mixed>
     *
     * @throws InvalidMessage
     * @throws TypeError
     * @codeCoverageIgnore
     */
    public static function unpackMessageForDecryption(string $ciphertext): array
    {
        $length = Binary::safeStrlen($ciphertext);

        // Fail fast on invalid messages
        if ($length < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                'Message is too short'
            );
        }

        // The first 4 bytes are reserved for the version size
        $version = Binary::safeSubstr(
            $ciphertext,
            0,
            Halite::VERSION_TAG_LEN
        );
        $config = SymmetricConfig::getConfig($version, 'encrypt');

        if ($length < $config->SHORTEST_CIPHERTEXT_LENGTH) {
            throw new InvalidMessage(
                'Message is too short'
            );
        }

        // The salt is used for key splitting (via HKDF)
        $salt = Binary::safeSubstr(
            $ciphertext,
            Halite::VERSION_TAG_LEN,
            (int) $config->HKDF_SALT_LEN
        );

        // This is the nonce (we authenticated it):
        $nonce = Binary::safeSubstr(
            $ciphertext,
            // 36:
            Halite::VERSION_TAG_LEN + (int) $config->HKDF_SALT_LEN,
            // 24:
            SODIUM_CRYPTO_STREAM_NONCEBYTES
        );

        // This is the crypto_stream_xor()ed ciphertext
        $encrypted = Binary::safeSubstr(
            $ciphertext,
            // 60:
            Halite::VERSION_TAG_LEN +
            (int) $config->HKDF_SALT_LEN +
            SODIUM_CRYPTO_STREAM_NONCEBYTES,
            // $length - 124
            $length - (
                Halite::VERSION_TAG_LEN +
                (int) $config->HKDF_SALT_LEN +
                SODIUM_CRYPTO_STREAM_NONCEBYTES +
                (int) $config->MAC_SIZE
            )
        );

        // $auth is the last 32 bytes
        $auth = Binary::safeSubstr(
            $ciphertext,
            $length - (int) $config->MAC_SIZE
        );

        // We don't need this anymore.
        Util::memzero($ciphertext);

        // Now we return the pieces in a specific order:
        return [$version, $config, $salt, $nonce, $encrypted, $auth];
    }

    /**
     * Verify the authenticity of a message, given a shared MAC key
     *
     * @param string $message
     * @param AuthenticationKey $secretKey
     * @param string $mac
     * @param string|bool $encoding
     * @param ?SymmetricConfig $config
     *
     * @return bool
     *
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(
        string $message,
        AuthenticationKey $secretKey,
        string $mac,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE,
        ?SymmetricConfig $config = null
    ): bool {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            /** @var string $mac */
            $mac = $decoder($mac);
        }
        if (is_null($config)) {
            // Default to the current version
            $config = SymmetricConfig::getConfig(
                Halite::HALITE_VERSION,
                'auth'
            );
        }
        try {
            return self::verifyMAC(
                $mac,
                $message,
                $secretKey->getRawKeyMaterial(),
                $config
            );
        // @codeCoverageIgnoreStart
        } catch (InvalidMessage $ex) {
            return false;
        // @codeCoverageIgnoreEnd
        }
    }

    /**
     * Calculate a MAC. This is used internally.
     *
     * @param string $message
     * @param string $authKey
     * @param SymmetricConfig $config
     *
     * @return string
     *
     * @throws InvalidMessage
     * @throws SodiumException
     */
    protected static function calculateMAC(
        string $message,
        string $authKey,
        SymmetricConfig $config
    ): string {
        if ($config->MAC_ALGO === 'BLAKE2b') {
            return sodium_crypto_generichash(
                $message,
                $authKey,
                (int) $config->MAC_SIZE
            );
        }
        // @codeCoverageIgnoreStart
        throw new InvalidMessage(
            'Invalid Halite version'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Verify a Message Authentication Code (MAC) of a message, with a shared
     * key.
     *
     * @param string $mac              Message Authentication Code
     * @param string $message          The message to verify
     * @param string $authKey          Authentication key (symmetric)
     * @param SymmetricConfig $config  Configuration object
     *
     * @return bool
     *
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws SodiumException
     */
    protected static function verifyMAC(
        string $mac,
        string $message,
        string $authKey,
        SymmetricConfig $config
    ): bool {
        if (Binary::safeStrlen($mac) !== $config->MAC_SIZE) {
            // @codeCoverageIgnoreStart
            throw new InvalidSignature(
                'Argument 1: Message Authentication Code is not the correct length; is it encoded?'
            );
            // @codeCoverageIgnoreEnd
        }
        if ($config->MAC_ALGO === 'BLAKE2b') {
            $calc = sodium_crypto_generichash(
                $message,
                $authKey,
                (int) $config->MAC_SIZE
            );
            $res = hash_equals($mac, $calc);
            Util::memzero($calc);
            return $res;
        }
        // @codeCoverageIgnoreStart
        throw new InvalidMessage(
            'Invalid Halite version'
        );
        // @codeCoverageIgnoreEnd
    }
}
