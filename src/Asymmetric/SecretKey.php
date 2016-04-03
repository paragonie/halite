<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Alerts\CannotPerformOperation;

class SecretKey extends Key
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool[] $args
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        $signing = \count($args) >= 1
            ? $args[0]
            : false;
        parent::__construct($keyMaterial, false, $signing, true);
    }
    
    /**
     * See the appropriate derived class.
     */
    public function derivePublicKey()
    {
        throw new CannotPerformOperation(
            'This is not implemented in the base class'
        );
    }
}
