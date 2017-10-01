<?php
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;

class SecretKey extends Key implements Contract\KeyInterface
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        /** @var bool $signing */
        $signing = \count($args) >= 1 ? $args[0] : false;
        parent::__construct($keyMaterial, false, $signing, false);
    }
}
