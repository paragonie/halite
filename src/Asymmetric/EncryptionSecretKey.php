<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class EncryptionSecretKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', $public=false,$signing=false,$asymmetric=false)
    {
        // X25519 keys are a fixed size
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_BOX_SECRETKEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Encryption secret key must be CRYPTO_BOX_SECRETKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, false);
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return SignaturePublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \Sodium\crypto_box_publickey_from_secretkey(
            $this->get()
        );
        return new EncryptionPublicKey($publicKey);
    }
}
