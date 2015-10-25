<?php
namespace ParagonIE\Halite\Asymmetric;

class SignaturePublicKey extends PublicKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        parent::__construct($keyMaterial, true);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_SIGN, &$secret_key = null)
    {
        if (self::hasFlag($type, self::ENCRYPTION)) {
            $type &= ~self::ENCRYPTION;
        }
        return parent::generate($type, $secret_key);
    }
}
