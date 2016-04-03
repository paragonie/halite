<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Key;

class SecretKey extends Key
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool[] $args
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        $signing = \count($args) >= 1 ? $args[0] : false;
        parent::__construct($keyMaterial, false, $signing, false);
    }
}
