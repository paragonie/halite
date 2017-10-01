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
    public function __construct($keyMaterial = '', ...$args) 
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
     * @return EncryptionPublicKey
     */
    public function derivePublicKey()
    {
        /** @var string $publicKey */
        $publicKey = \Sodium\crypto_box_publickey_from_secretkey(
            $this->get()
        );
        return new EncryptionPublicKey($publicKey);
    }
}
