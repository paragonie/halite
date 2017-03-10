<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class SignatureSecretKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool   $public
     * @param bool   $signing - Is this a signing key?
     * @param bool   $asymmetric
     * @throws CryptoException\InvalidKey
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false, $asymmetric = false)
    {
        // Ed25519 keys are a fixed size
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, false, true);
    }

    /**
     * See the appropriate derived class.
     *
     * @return SignaturePublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \Sodium\crypto_sign_publickey_from_secretkey(
            $this->get()
        );
        return new SignaturePublicKey($publicKey);
    }
}
