<?php
namespace ParagonIE\Halite\Symmetric;

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
        parent::__construct($keyMaterial, false, $signing, false);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_SECRETBOX, &$secret_key = null)
    {
        if ($type & self::ASYMMETRIC !== 0) {
            $type ^= self::ASYMMETRIC;
        }
        if ($type & self::PUBLIC_KEY !== 0) {
            $type ^= self::PUBLIC_KEY;
        }
        // Force secret key
        $type &= self::SECRET_KEY;
        parent::generate($type, $secret_key);
    }
}
