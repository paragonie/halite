<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Symmetric\Crypto as Symmetric;

class Password implements \ParagonIE\Halite\Contract\Crypto\PasswordInterface
{
    /**
     * Hash then encrypt a password
     * 
     * @param string $password   - The user's password
     * @param Key $secret_key - The master key for all passwords
     * @return string
     */
    public static function hash($password, \ParagonIE\Halite\Contract\CryptoKeyInterface $secret_key)
    {
        // First, let's calculate the hash
        $hashed = \Sodium\crypto_pwhash_scryptsalsa208sha256_str(
            $password,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        
        // Now let's encrypt the result
        return Symmetric::encrypt($hashed, $secret_key);
    }

    /**
     * Decrypt then verify a password
     * 
     * @param string $password - The user-provided password
     * @param string $stored   - The encrypted password hash
     * @param Key $secret_key  - The master key for all passwords
     */
    public static function verify($password, $stored, \ParagonIE\Halite\Contract\CryptoKeyInterface $secret_key)
    {
        // First let's decrypt the hash
        $hash_str = Symmetric::decrypt($stored, $secret_key);
        // And now to verify the hash
        return \Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $password);
    }
}
