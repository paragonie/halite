<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class EncryptionSecretKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool[] $args
     * @throws InvalidKey
     */
    public function __construct(string $keyMaterial = '', ...$args)
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidKey(
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
            $this->getRawKeyMaterial()
        );
        return new EncryptionPublicKey($publicKey);
    }
}
