<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Util as CryptoUtil;

/**
 * Class SignatureSecretKey
 * @package ParagonIE\Halite\Asymmetric
 */
final class SignatureSecretKey extends SecretKey
{
    /**
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     */
    public function __construct(HiddenString $keyMaterial)
    {
        if (CryptoUtil::safeStrlen($keyMaterial->getString()) !== \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKey(
                'Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial);
        $this->isSigningKey = true;
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return SignaturePublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \sodium_crypto_sign_publickey_from_secretkey(
            $this->getRawKeyMaterial()
        );
        return new SignaturePublicKey(new HiddenString($publicKey));
    }
}
