<?php
namespace ParagonIE\Halite\Contract;

/**
 * An interface fundamental to all cryptography implementations
 */
interface CryptoInterface 
{
    /**
     * Generate an encryption key
     * 
     * @param $type
     * @return Key
     */
    public static function generateKeys($type);
    
}
