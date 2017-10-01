<?php
namespace ParagonIE\Halite\Contract;
/**
 * An inferface for cryptographic secrets -- They should be protected!
 */
interface KeyInterface
{
    /**
     * Don't let this ever succeed
     */
    public function __clone();
    
    /**
     * @param string $keyMaterial
     * 
     * Plus optional arguments
     */
    public function __construct($keyMaterial = '', ...$args);
    
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

    /**
     * We rename this in version 2. Keep this for now.
     *
     * @return string
     */
    public function get();

    /**
     * Get the actual key material
     *
     * @return string
     */
    public function getRawKeyMaterial();
}
