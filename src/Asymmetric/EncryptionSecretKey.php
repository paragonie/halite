<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Util as CryptoUtil;

/**
 * Class EncryptionSecretKey
 * @package ParagonIE\Halite\Asymmetric
 */
final class EncryptionSecretKey extends SecretKey
{
    /**
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     */
    public function __construct(HiddenString $keyMaterial)
    {
        if (CryptoUtil::safeStrlen($keyMaterial->getString()) !== \SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidKey(
                'Encryption secret key must be CRYPTO_BOX_SECRETKEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial);
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return EncryptionPublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \sodium_crypto_box_publickey_from_secretkey(
            $this->getRawKeyMaterial()
        );
        return new EncryptionPublicKey(
            new HiddenString($publicKey)
        );
    }
}
