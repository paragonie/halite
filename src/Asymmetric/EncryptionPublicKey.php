<?php
namespace ParagonIE\Halite\Asymmetric;

class EncryptionPublicKey extends PublicKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        parent::__construct($keyMaterial, false);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_BOX, &$secret_key = null)
    {
        if (self::hasFlag($type, self::SIGNATURE)) {
            $type &= ~self::SIGNATURE;
        }
        return parent::generate($type, $secret_key);
    }
}
