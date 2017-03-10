<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Alerts\CannotPerformOperation;

class SecretKey extends Key implements Contract\KeyInterface
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool   $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false, $asymmetric = false)
    {
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
