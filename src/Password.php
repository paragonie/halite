<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Halite\{
    Alerts\InvalidMessage,
    Symmetric\Config as SymmetricConfig,
    Symmetric\Crypto,
    Symmetric\EncryptionKey
};

/**
 * Class Password
 *
 * Secure password storage and secure password verification
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 */
final class Password
{
    /**
     * Hash then encrypt a password
     *
     * @param HiddenString $password    The user's password
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @param string $level             The security level for this password
     * @return string                   An encrypted hash to store
     */
    public static function hash(
        HiddenString $password,
        EncryptionKey $secretKey,
        string $level = KeyFactory::INTERACTIVE
    ): string {
        $kdfLimits = KeyFactory::getSecurityLevels($level);
        // First, let's calculate the hash
        $hashed = \sodium_crypto_pwhash_str(
            $password->getString(),
            $kdfLimits[0],
            $kdfLimits[1]
        );
        
        // Now let's encrypt the result
        return Crypto::encrypt(
            new HiddenString($hashed),
            $secretKey
        );
    }

    /**
     * Is this password hash stale?
     *
     * @param string $stored            Encrypted password hash
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @param string $level             The security level for this password
     * @return bool                     Do we need to regenerate the hash or
     *                                  ciphertext?
     * @throws InvalidMessage
     */
    public static function needsRehash(
        string $stored,
        EncryptionKey $secretKey,
        string $level = KeyFactory::INTERACTIVE
    ): bool {
        $config = self::getConfig($stored);
        if (Util::safeStrlen($stored) < ($config->SHORTEST_CIPHERTEXT_LENGTH * 4 / 3)) {
            throw new InvalidMessage('Encrypted password hash is too short.');
        }

        // First let's decrypt the hash
        $hash_str = Crypto::decrypt(
            $stored,
            $secretKey,
            $config->ENCODING
        )->getString();

        // Upon successful decryption, verify that we're using Argon2i
        if (!\hash_equals(
            Util::safeSubstr($hash_str, 0, 9),
            SODIUM_CRYPTO_PWHASH_STRPREFIX
        )) {
            return true;
        }

        // Parse the cost parameters:
        switch ($level) {
            case KeyFactory::INTERACTIVE:
                return !\hash_equals(
                    '$argon2i$v=19$m=32768,t=4,p=1$',
                    Util::safeSubstr($hash_str, 0, 30)
                );
            case KeyFactory::MODERATE:
                return !\hash_equals(
                    '$argon2i$v=19$m=131072,t=6,p=1$',
                    Util::safeSubstr($hash_str, 0, 31)
                );
            case KeyFactory::SENSITIVE:
                return !\hash_equals(
                    '$argon2i$v=19$m=524288,t=8,p=1$',
                    Util::safeSubstr($hash_str, 0, 31)
                );
            default:
                return true;
        }
    }

    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   A stored password hash
     * @return SymmetricConfig
     * @throws InvalidMessage
     */
    protected static function getConfig(string $stored): SymmetricConfig
    {
        $length = Util::safeStrlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new InvalidMessage(
                'Encrypted password hash is way too short.'
            );
        }
        if (\hash_equals(Util::safeSubstr($stored, 0, 5), Halite::VERSION_PREFIX)) {
            return SymmetricConfig::getConfig(
                Base64UrlSafe::decode($stored),
                'encrypt'
            );
        }
        $v = \hex2bin(Util::safeSubstr($stored, 0, 8));
        return SymmetricConfig::getConfig($v, 'encrypt');
    }

    /**
     * Decrypt then verify a password
     *
     * @param HiddenString $password    The user's password
     * @param string $stored            The encrypted password hash
     * @param EncryptionKey $secretKey  The master key for all passwords
     * @return bool                     Is this password valid?
     * @throws InvalidMessage
     */
    public static function verify(
        HiddenString $password,
        string $stored,
        EncryptionKey $secretKey
    ): bool {
        $config = self::getConfig($stored);
        // Base64-urlsafe encoded, so 4/3 the size of raw binary
        if (Util::safeStrlen($stored) < ($config->SHORTEST_CIPHERTEXT_LENGTH * 4/3)) {
            throw new InvalidMessage(
                'Encrypted password hash is too short.'
            );
        }
        // First let's decrypt the hash
        $hash_str = Crypto::decrypt($stored, $secretKey, $config->ENCODING);
        // Upon successful decryption, verify the password is correct
        return \sodium_crypto_pwhash_str_verify(
            $hash_str->getString(),
            $password->getString()
        );
    }
}
