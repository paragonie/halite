<?php
namespace ParagonIE\Halite\Symmetric;

class AuthenticationKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     */
    public function __construct($keyMaterial = '', ...$args)
    {
        parent::__construct($keyMaterial, true);
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
    public static function deriveFromPassword($password, $salt, $type = self::CRYPTO_AUTH)
    {
        if (self::hasFlag($type, self::ENCRYPTION)) {
            $type &= ~self::ENCRYPTION;
        }
        return parent::deriveFromPassword($password, $salt, $type);
    }
    
    /**
     * See Key::generate()
     * 
     * @param type $type
     * @param type $secret_key
     */
    public static function generate($type = self::CRYPTO_AUTH, &$secret_key = null)
    {
        if (self::hasFlag($type, self::ENCRYPTION)) {
            $type &= ~self::ENCRYPTION;
        }
        return parent::generate($type, $secret_key);
    }
}
