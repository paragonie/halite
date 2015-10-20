<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;

class PublicKey extends \ParagonIE\Halite\Key implements Contract\CryptoKeyInterface
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        $signing = \count($args) >= 1
            ? $args[0]
            : false;
        parent::__construct($keyMaterial, true, $signing, true);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_BOX, &$secret_key = null)
    {
        if (!self::hasFlag($type, self::ASYMMETRIC)) {
            $type |= self::ASYMMETRIC;
        }
        return parent::generate($type, $secret_key);
    }
}
