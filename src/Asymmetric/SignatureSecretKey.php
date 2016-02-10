<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class SignatureSecretKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKey(
                'Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, true);
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return SignaturePublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \Sodium\crypto_sign_publickey_from_secretkey(
            $this->getRawKeyMaterial()
        );
        return new SignaturePublicKey($publicKey);
    }
}
