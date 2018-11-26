<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;

/**
 * Class EncryptionSecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class EncryptionSecretKey extends SecretKey
{
    /**
     * EncryptionSecretKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     * @throws \TypeError
     */
    public function __construct(HiddenString $keyMaterial)
    {
        if (Binary::safeStrlen($keyMaterial->getString()) !== \SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
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
     *
     * @throws InvalidKey
     * @throws \TypeError
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
