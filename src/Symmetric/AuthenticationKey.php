<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class AuthenticationKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool[] $args
     * @throws InvalidKey
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidKey(
                'Authentication key must be CRYPTO_AUTH_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, true);
    }
}
