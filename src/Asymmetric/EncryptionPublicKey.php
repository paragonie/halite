<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use const SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;
use function sprintf;

/**
 * Class EncryptionPublicKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class EncryptionPublicKey extends PublicKey
{
    /**
     * EncryptionPublicKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws \TypeError
     */
    public function __construct(HiddenString $keyMaterial)
    {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Encryption public key must be CRYPTO_BOX_PUBLICKEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_BOX_PUBLICKEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial);
    }
}
