<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;
use TypeError;
use const SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
use function
    sodium_crypto_box_publickey_from_secretkey,
    sprintf;

/**
 * Class EncryptionSecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class EncryptionSecretKey extends SecretKey
{
    /**
     * EncryptionSecretKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\SensitiveParameter]
        HiddenString $keyMaterial,
        ?HiddenString $pk = null
    ) {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Encryption secret key must be CRYPTO_BOX_SECRETKEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_BOX_SECRETKEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial, $pk);
    }

    /**
     * See the appropriate derived class.
     *
     * @return EncryptionPublicKey
     *
     * @throws InvalidKey
     * @throws TypeError
     * @throws SodiumException
     */
    public function derivePublicKey(): EncryptionPublicKey
    {
        if (is_null($this->cachedPublicKey)) {
            $this->cachedPublicKey = sodium_crypto_box_publickey_from_secretkey(
                $this->getRawKeyMaterial()
            );
        }
        return new EncryptionPublicKey(
            new HiddenString($this->cachedPublicKey)
        );
    }
}
