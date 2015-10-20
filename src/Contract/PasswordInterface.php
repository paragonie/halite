<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;

/**
 * Hash then encrypt
 */
interface PasswordInterface 
{
    
    /**
     * Hash then encrypt a password
     * 
     * @param string $password   - The user's password
     * @param Key $secret_key - The master key for all passwords
     * @return string
     */
    public static function hash($password, SymmetricKey $secret_key);
    
    /**
     * Decrypt then verify a password
     * 
     * @param string $password - The user-provided password
     * @param string $stored   - The encrypted password hash
     * @param Key $secret_key  - The master key for all passwords
     */
    public static function verify($password, $stored, SymmetricKey $secret_key);
}
