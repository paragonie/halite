<?php
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Contract;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\Alerts\CannotPerformOperation;

/**
 * Class SecretKey
 * @package ParagonIE\Halite\Asymmetric
 */
class SecretKey extends Key
{
    /**
     * @param string $keyMaterial - The actual key data
     */
    public function __construct(string $keyMaterial = '')
    {
        parent::__construct($keyMaterial);
        $this->is_asymmetric_key = true;
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
