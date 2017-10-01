<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Contract;

/**
 * Symmetric Key Crypography uses one secret key, while Asymmetric Key Cryptography
 * uses a secret key and public key pair
 */
abstract class Key implements Contract\KeyInterface
{
    // FLAGS:
    const SECRET_KEY       =   1;
    const PUBLIC_KEY       =   2;
    const ENCRYPTION       =   4;
    const SIGNATURE        =   8;
    const ASYMMETRIC       =  16;
    
    // ALIAS:
    const AUTHENTICATION   =   8;
    
    // SHORTCUTS:
    const CRYPTO_SECRETBOX =  5;
    const CRYPTO_AUTH      =  9;
    const CRYPTO_BOX       = 20;
    const CRYPTO_SIGN      = 24;

    /** @var bool $is_public_key */
    private $is_public_key = false;

    /** @var bool $is_signing_key */
    private $is_signing_key = false;

    /** @var bool $is_asymmetric_key */
    private $is_asymmetric_key = false;

    /** @var string $key_material */
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
     * @param string $keyMaterial - The actual key data
     * @param bool $public - Is this a public key?
     * @param bool $signing - Is this a signing key?
     * @param bool $asymmetric - Is this being used in asymmetric cryptography?
     */
    public function __construct(
        $keyMaterial = '',
        ...$args
    ) {
        // Workaround: Inherited classes have simpler constructors:
        $public = (bool) (\count($args) >= 1 ? $args[0] : false);
        $signing = (bool) (\count($args) >= 2 ? $args[1] : false);
        $asymmetric = (bool) (\count($args) >= 3 ? $args[2] : false);
        
        // String concatenation used to undo a PHP 7 optimization that causes
        // the wrong memory to get overwritten by \Sodium\memzero:
        $this->key_material .= $keyMaterial;
        $this->is_public_key = !empty($public);
        $this->is_signing_key = !empty($signing);
        if ($public && !$asymmetric) {
            // This is implied.
            $asymmetric = true;
        }
        $this->is_asymmetric_key = !empty($asymmetric);
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
            $this->key_material = '';
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
     * We rename this in version 2. Keep this for now.
     *
     * @return string
     */
    public function get()
    {
        return $this->getRawKeyMaterial();
    }
    
    /**
     * Get the actual key material
     * 
     * @return string
     */
    public function getRawKeyMaterial()
    {
        return ''.$this->key_material;
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
    
    /**
     * Does this integer contain this flag?
     * 
     * @param int $int
     * @param int $flag
     * @return bool
     */
    public static function hasFlag($int, $flag)
    {
        return ($int & $flag) !== 0;
    }
    
    /**
     * Opposite of hasFlag()
     * 
     * @param int $int
     * @param int $flag
     * @return bool
     */
    public static function doesNotHaveFlag($int, $flag)
    {
        return ($int & $flag) === 0;
    }
}
