<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use TypeError;
use const SODIUM_CRYPTO_STREAM_KEYBYTES;
use function sprintf;

/**
 * Class EncryptionKey
 * @package ParagonIE\Halite\Symmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class EncryptionKey extends SecretKey
{
    /**
     * EncryptionKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\SensitiveParameter]
        HiddenString $keyMaterial
    ) {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_STREAM_KEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Encryption key must be CRYPTO_STREAM_KEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_STREAM_KEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial);
    }
}
