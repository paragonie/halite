<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class SignaturePublicKey extends PublicKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKey(
                'Signature public key must be CRYPTO_SIGN_PUBLICKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, true);
    }
}
