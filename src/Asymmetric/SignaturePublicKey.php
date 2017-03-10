<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class SignaturePublicKey extends PublicKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool   $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false, $asymmetric = false)
    {
        // Ed25519 keys are a fixed size
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Signature public key must be CRYPTO_SIGN_PUBLICKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, true, true);
    }
}
