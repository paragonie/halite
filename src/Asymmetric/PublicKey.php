<?php
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Contract;

class PublicKey extends \ParagonIE\Halite\Key implements Contract\CryptoKeyInterface
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        $signing = \count($args) >= 1 ? $args[0] : false;
        parent::__construct($keyMaterial, true, $signing, true);
    }
}
