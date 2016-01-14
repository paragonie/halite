<?php
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class EncryptionKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     */
    public function __construct($keyMaterial = '', ...$args)
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_STREAM_KEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Encryption key must be CRYPTO_STREAM_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, false);
    }
}
