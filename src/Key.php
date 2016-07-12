<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Contract;

/**
 * Class Key
 *
 * Base class for all cryptography secrets
 *
 * @package ParagonIE\Halite
 */
class Key
{
    protected $is_public_key = false;
    protected $is_signing_key = false;
    protected $is_asymmetric_key = false;
    private $key_material = '';
    
    /**
     * Don't let this ever succeed
     * 
     * @throws CryptoException\CannotCloneKey
     */
    public function __clone()
    {
        throw new CryptoException\CannotCloneKey;
    }
    
    /**
     * You probably should not be using this directly.
     *
     * @param HiddenString $keyMaterial - The actual key data
     */
    public function __construct(HiddenString $keyMaterial)
    {
        $this->key_material = Util::safeStrcpy($keyMaterial->getString());
    }

    /**
     * Hide this from var_dump(), etc.
     * 
     * @return array
     */
    public function __debugInfo()
    {
        // We exclude $this->key_material
        return [
            'is_asymmetric_key' => $this->is_asymmetric_key,
            'is_public_key' => $this->is_public_key,
            'is_signing_key' => $this->is_signing_key
        ];
    }
    
    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct()
    {
        if (!$this->is_public_key) {
            \Sodium\memzero($this->key_material);
            $this->key_material = null;
        }
    }
    
    /**
     * Don't allow this object to ever be serialized
     */
    public function __sleep()
    {
        throw new CryptoException\CannotSerializeKey;
    }
    
    /**
     * Get public keys
     * 
     * @return string
     */
    public function __toString()
    {
        if ($this->is_public_key) {
            return $this->key_material;
        }
        return '';
    }
    /**
     * Get the actual key material
     * 
     * @return string
     */
    public function getRawKeyMaterial()
    {
        return Util::safeStrcpy($this->key_material);
    }
    
    /**
     * Is this a part of a key pair?
     * 
     * @return bool
     */
    public function isAsymmetricKey()
    {
        return $this->is_asymmetric_key;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isEncryptionKey()
    {
        return !$this->is_signing_key;
    }
    
    /**
     * Is this a public key?
     * 
     * @return bool
     */
    public function isPublicKey()
    {
        return $this->is_public_key;
    }
    
    /**
     * Is this a secret key?
     * 
     * @return bool
     */
    public function isSecretKey()
    {
        return !$this->is_public_key;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isSigningKey()
    {
        return $this->is_signing_key;
    }
}
