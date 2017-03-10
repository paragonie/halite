<?php
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class AuthenticationKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool   $public
     * @param bool   $signing
     * @param bool   $asymmetric
     * @throws CryptoException\InvalidKey
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false, $asymmetric = false)
    {
        // HMAC-SHA512/256 keys are a fixed size
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_AUTH_KEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Authentication key must be CRYPTO_AUTH_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, false, true);
    }
}
