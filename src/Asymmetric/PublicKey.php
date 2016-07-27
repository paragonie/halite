<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Key;

/**
 * Class PublicKey
 * @package ParagonIE\Halite\Asymmetric
 */
class PublicKey extends Key
{
    /**
     * @param HiddenString $keyMaterial - The actual key data
     */
    public function __construct(HiddenString $keyMaterial)
    {
        parent::__construct($keyMaterial);
        $this->isAsymmetricKey = true;
        $this->isPublicKey = true;
    }
}
