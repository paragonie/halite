<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class AuthenticationKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @throws InvalidKey
     */
    public function __construct(string $keyMaterial = '')
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidKey(
                'Authentication key must be CRYPTO_AUTH_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, true);
        $this->is_signing_key = true;
    }
}
