<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use \ParagonIE\Halite\{
    Alerts\InvalidMessage,
    Symmetric\Config as SymmetricConfig,
    Symmetric\Crypto,
    Symmetric\EncryptionKey,
    Util as CryptoUtil
};

/**
 * Secure password storage and secure password verification
 */
abstract class Password
{
    /**
     * Hash then encrypt a password
     * 
     * @param string $password          - The user's password
     * @param EncryptionKey $secret_key - The master key for all passwords
     * @return string
     */
    public static function hash(string $password, EncryptionKey $secret_key): string
    {
        // First, let's calculate the hash
        $hashed = \Sodium\crypto_pwhash_str(
            $password,
            \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        
        // Now let's encrypt the result
        return Crypto::encrypt($hashed, $secret_key);
    }

    /**
     * Is this password hash stale?
     *
     * @param string $stored            - A stored password hash
     * @param EncryptionKey $secret_key - The master key for all passwords
     * @return bool
     * @throws InvalidMessage
     */
    public static function needsRehash(string $stored, EncryptionKey $secret_key): bool
    {
        $config = self::getConfig($stored);
        $v = \Sodium\hex2bin(CryptoUtil::safeSubstr($stored, 0, 8));
        if (!\hash_equals(Halite::HALITE_VERSION, $v)) {
            // Outdated version of the library; Always rehash without decrypting
            return true;
        }
        if (CryptoUtil::safeStrlen($stored) < ($config->SHORTEST_CIPHERTEXT_LENGTH * 2)) {
            throw new InvalidMessage('Encrypted password hash is too short.');
        }

        // First let's decrypt the hash
        $hash_str = Crypto::decrypt($stored, $secret_key);

        // Upon successful decryption, verify that we're using Argon2i
        return !\hash_equals(
            CryptoUtil::safeSubstr($hash_str, 0, 9),
            \Sodium\CRYPTO_PWHASH_STRPREFIX
        );
    }

    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   - A stored password hash
     * @return SymmetricConfig
     * @throws InvalidMessage
     */
    protected static function getConfig(string $stored): SymmetricConfig
    {
        $length = CryptoUtil::safeStrlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new InvalidMessage('Encrypted password hash is way too short.');
        }
        $v = \Sodium\hex2bin(CryptoUtil::safeSubstr($stored, 0, 8));
        return SymmetricConfig::getConfig($v, 'encrypt');
    }

    /**
     * Decrypt then verify a password
     * 
     * @param string $password           - The user-provided password
     * @param string $stored             - The encrypted password hash
     * @param EncryptionKey $secret_key  - The master key for all passwords
     * @return boolean
     * @throws InvalidMessage
     */
    public static function verify(
        string $password,
        string $stored,
        EncryptionKey $secret_key
    ): bool {
        $config = self::getConfig($stored);
        // Hex-encoded, so the minimum ciphertext length is double:
        if (CryptoUtil::safeStrlen($stored) < ($config->SHORTEST_CIPHERTEXT_LENGTH * 2)) {
            throw new InvalidMessage('Encrypted password hash is too short.');
        }
        // First let's decrypt the hash
        $hash_str = Crypto::decrypt($stored, $secret_key);
        // Upon successful decryption, verify the password is correct
        $isArgon2 = \hash_equals(
            CryptoUtil::safeSubstr($hash_str, 0, 9),
            \Sodium\CRYPTO_PWHASH_STRPREFIX
        );
        $isScrypt = \hash_equals(
            CryptoUtil::safeSubstr($hash_str, 0, 3),
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX
        );
        if ($isArgon2) {
            return \Sodium\crypto_pwhash_str_verify($hash_str, $password);
        } elseif ($isScrypt) {
            return \Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $password);
        }
        return false;
    }
}
