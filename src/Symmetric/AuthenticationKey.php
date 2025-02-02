<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Symmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use TypeError;
use const SODIUM_CRYPTO_AUTH_KEYBYTES;
use function sprintf;

/**
 * Class AuthenticationKey
 * @package ParagonIE\Halite\Symmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class AuthenticationKey extends SecretKey
{
    /**
     * AuthenticationKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\SensitiveParameter]
        HiddenString $keyMaterial
    ) {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Authentication key must be CRYPTO_AUTH_KEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_AUTH_KEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial);
        $this->isSigningKey = true;
    }
}
