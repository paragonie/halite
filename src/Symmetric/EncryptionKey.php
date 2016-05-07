<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use \ParagonIE\Halite\Alerts\InvalidKey;
use \ParagonIE\Halite\Util as CryptoUtil;

final class EncryptionKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @throws InvalidKey
     */
    public function __construct(string $keyMaterial = '')
    {
        if (CryptoUtil::safeStrlen($keyMaterial) !== \Sodium\CRYPTO_STREAM_KEYBYTES) {
            throw new InvalidKey(
                'Encryption key must be CRYPTO_STREAM_KEYBYTES bytes long'
            );
        }
        parent::__construct($keyMaterial);
    }
}
