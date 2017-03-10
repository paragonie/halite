<?php
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Alerts as CryptoException;

final class EncryptionKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool   $public
     * @param bool   $signing
     * @param bool   $asymmetric
     * @throws CryptoException\InvalidKey
     */
    public function __construct($keyMaterial = '', $public = false, $signing = false, $asymmetric = false)
    {
        // Longer keys are OK here; it gets blended through HKDF anyway.
        // We're only blocking weak keys here.
        if (CryptoUtil::safeStrlen($keyMaterial) < \Sodium\CRYPTO_STREAM_KEYBYTES) {
            throw new CryptoException\InvalidKey(
                'Encryption key must be at least CRYPTO_STREAM_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial, false, false);
    }
}
