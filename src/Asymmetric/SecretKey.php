<?php
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Contract;

class SecretKey extends \ParagonIE\Halite\Key implements Contract\CryptoKeyInterface
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        $signing = \count($args) >= 1 ? $args[0] : false;
        parent::__construct($keyMaterial, false, $signing, true);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_BOX, &$secret_key = null)
    {
        if ($type & self::ASYMMETRIC === 0) {
            $type &= self::ASYMMETRIC;
        }
        parent::generate($type, $secret_key);
    }
}
