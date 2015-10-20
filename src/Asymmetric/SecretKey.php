<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;

class SecretKey extends \ParagonIE\Halite\Key implements Contract\CryptoKeyInterface
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
        parent::__construct($keyMaterial, false, $signing, true);
    }
    
    /**
     * Derive an encryption key from a password and a salt
     * 
     * @param string $password
     * @param string $salt
     * @param int $type
     * @return array|\ParagonIE\Halite\Key
     * @throws CryptoException\InvalidFlags
     */
    public static function deriveFromPassword($password, $salt, $type = self::CRYPTO_BOX)
    {
        if (!self::hasFlag($type, self::ASYMMETRIC)) {
            $type |= self::ASYMMETRIC;
        }
        return parent::deriveFromPassword($password, $salt, $type);
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
