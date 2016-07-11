<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\Halite\Key;

/**
 * Class SecretKey
 * @package ParagonIE\Halite\Symmetric
 */
class SecretKey extends Key
{
    /**
     * @param string $keyMaterial - The actual key data
     */
    public function __construct(string $keyMaterial = '')
    {
        parent::__construct($keyMaterial);
    }
}
