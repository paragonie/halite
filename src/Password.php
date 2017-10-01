<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Alerts\InvalidType;
use \ParagonIE\Halite\Contract\KeyInterface;
use \ParagonIE\Halite\Symmetric\Crypto;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

/**
 * Secure password storage and secure password verification
 */
abstract class Password implements \ParagonIE\Halite\Contract\PasswordInterface
{
    /**
     * Hash then encrypt a password
     * 
     * @param string $password         - The user's password
     * @param EncryptionKey $secret_key - The master key for all passwords
     * @return string
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function hash($password, KeyInterface $secret_key)
    {
        if (!\is_string($password)) {
            throw new InvalidType(
                'Argument 1: Expected a string'
            );
        }
        if (!($secret_key instanceof EncryptionKey)) {
            throw new InvalidKey(
                'Argument 2: Expected an instance of EncryptionKey'
            );
        }
        // First, let's calculate the hash
        /** @var string $hashed */
        $hashed = \Sodium\crypto_pwhash_scryptsalsa208sha256_str(
            $password,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        
        // Now let's encrypt the result
        /** @var string $encrypted */
        $encrypted = Crypto::encrypt($hashed, $secret_key);
        return (string) $encrypted;
    }

    /**
     * Decrypt then verify a password
     * 
     * @param string $password          - The user-provided password
     * @param string $stored            - The encrypted password hash
     * @param EncryptionKey $secret_key  - The master key for all passwords
     * @return bool
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function verify($password, $stored, KeyInterface $secret_key)
    {
        if (!\is_string($password)) {
            throw new InvalidType(
                'Argument 1: Expected a string'
            );
        }
        if (!\is_string($stored)) {
            throw new InvalidType(
                'Argument 2: Expected a string'
            );
        }
        if (!($secret_key instanceof EncryptionKey)) {
            throw new InvalidKey(
                'Argument 3: Expected an instance of EncryptionKey'
            );
        }
        // First let's decrypt the hash
        $hash_str = Crypto::decrypt($stored, $secret_key);
        // Upon successful decryption, verify the password is correct
        return (bool) \Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $password);
    }
}
