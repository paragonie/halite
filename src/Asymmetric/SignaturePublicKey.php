<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;
use TypeError;
use const SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
use function
    sodium_crypto_sign_ed25519_pk_to_curve25519,
    sprintf;

/**
 * Class SignaturePublicKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class SignaturePublicKey extends PublicKey
{
    /**
     * SignaturePublicKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(HiddenString $keyMaterial)
    {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Signature public key must be CRYPTO_SIGN_PUBLICKEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial);
        $this->isSigningKey = true;
    }

    /**
     * Get an encryption public key from a signing public key.
     *
     * @return EncryptionPublicKey
     *
     * @throws SodiumException
     * @throws TypeError
     * @throws InvalidKey
     */
    public function getEncryptionPublicKey(): EncryptionPublicKey
    {
        $ed25519_pk = $this->getRawKeyMaterial();
        $x25519_pk = sodium_crypto_sign_ed25519_pk_to_curve25519(
            $ed25519_pk
        );
        return new EncryptionPublicKey(
            new HiddenString($x25519_pk)
        );
    }
}
