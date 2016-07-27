<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;

/**
 * Class Key
 *
 * Base class for all cryptography secrets
 *
 * @package ParagonIE\Halite
 */
class Key
{
    protected $isPublicKey = false;
    protected $isSigningKey = false;
    protected $isAsymmetricKey = false;
    private $keyMaterial = '';

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
        $this->keyMaterial = Util::safeStrcpy($keyMaterial->getString());
    }

    /**
     * Hide this from var_dump(), etc.
     *
     * @return array
     */
    public function __debugInfo()
    {
        // We exclude $this->keyMaterial
        return [
            'isAsymmetricKey' => $this->isAsymmetricKey,
            'isPublicKey' => $this->isPublicKey,
            'isSigningKey' => $this->isSigningKey
        ];
    }

    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct()
    {
        if (!$this->isPublicKey) {
            \Sodium\memzero($this->keyMaterial);
            $this->keyMaterial = null;
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
        if ($this->isPublicKey) {
            return $this->keyMaterial;
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
        return Util::safeStrcpy($this->keyMaterial);
    }
    
    /**
     * Is this a part of a key pair?
     * 
     * @return bool
     */
    public function isAsymmetricKey()
    {
        return $this->isAsymmetricKey;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isEncryptionKey()
    {
        return !$this->isSigningKey;
    }
    
    /**
     * Is this a public key?
     * 
     * @return bool
     */
    public function isPublicKey()
    {
        return $this->isPublicKey;
    }
    
    /**
     * Is this a secret key?
     * 
     * @return bool
     */
    public function isSecretKey()
    {
        return !$this->isPublicKey;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isSigningKey()
    {
        return $this->isSigningKey;
    }
}
