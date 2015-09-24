<?php
namespace ParagonIE\Halite\Contract;
/**
 * An inferface for cryptographic secrets -- They should be protected!
 */
interface CryptoKeyInterface
{
    /**
     * Don't let this ever succeed
     */
    public function __clone();
    
    /**
     * @param string $keyMaterial
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false);
    
    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct();
        
    /**
     * Wipe the key from memory before serializing
     */
    public function __sleep();
    
    /**
     * Is this a part of a key pair?
     * 
     * @return bool
     */
    public function isAsymmetricKey();
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isEncryptionKey();
    
    /**
     * Is this a public key?
     * 
     * @return bool
     */
    public function isPublicKey();
    
    /**
     * Is this a secret key?
     * 
     * @return bool
     */
    public function isSecretKey();
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isSigningKey();
}
