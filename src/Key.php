<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\{
    CannotCloneKey,
    CannotSerializeKey
};

/**
 * Class Key
 *
 * Base class for all cryptography secrets
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 */
class Key
{
    /**
     * @var bool
     */
    protected $isPublicKey = false;

    /**
     * @var bool
     */
    protected $isSigningKey = false;

    /**
     * @var bool
     */
    protected $isAsymmetricKey = false;

    /**
     * @var string
     */
    private $keyMaterial = '';

    /**
     * Don't let this ever succeed
     *
     * @throws CannotCloneKey
     */
    public function __clone()
    {
        throw new CannotCloneKey;
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
            \sodium_memzero($this->keyMaterial);
            $this->keyMaterial = '';
        }
    }

    /**
     * Don't allow this object to ever be serialized
     */
    public function __sleep()
    {
        throw new CannotSerializeKey;
    }

    /**
     * Don't allow this object to ever be unserialized
     */
    public function __wakeup()
    {
        throw new CannotSerializeKey;
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
    public function getRawKeyMaterial(): string
    {
        return Util::safeStrcpy($this->keyMaterial);
    }
    
    /**
     * Is this a part of a key pair?
     * 
     * @return bool
     */
    public function isAsymmetricKey(): bool
    {
        return $this->isAsymmetricKey;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isEncryptionKey(): bool
    {
        return !$this->isSigningKey;
    }
    
    /**
     * Is this a public key?
     * 
     * @return bool
     */
    public function isPublicKey(): bool
    {
        return $this->isPublicKey;
    }
    
    /**
     * Is this a secret key?
     * 
     * @return bool
     */
    public function isSecretKey(): bool
    {
        return !$this->isPublicKey;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isSigningKey(): bool
    {
        return $this->isSigningKey;
    }
}
