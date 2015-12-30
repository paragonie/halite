<?php
namespace ParagonIE\Halite\Symmetric;

final class AuthenticationKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     */
    public function __construct($keyMaterial = '', ...$args)
    {
        parent::__construct($keyMaterial, true);
    }
}
