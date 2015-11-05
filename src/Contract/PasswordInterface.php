<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Symmetric\EncryptionKey;

/**
 * Hash then encrypt
 */
interface PasswordInterface 
{
    
    /**
     * Hash then encrypt a password
     * 
     * @param string $password   - The user's password
     * @param EncryptionKey $secret_key - The master key for all passwords
     * @return string
     */
    public static function hash($password, KeyInterface $secret_key);
    
    /**
     * Decrypt then verify a password
     * 
     * @param string $password - The user-provided password
     * @param string $stored   - The encrypted password hash
     * @param EncryptionKey $secret_key  - The master key for all passwords
     * @return boolean
     */
    public static function verify($password, $stored, KeyInterface $secret_key);
}
