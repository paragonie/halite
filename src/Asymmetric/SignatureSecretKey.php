<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;
use TypeError;
use const
    SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;
use function
    sodium_crypto_sign_ed25519_sk_to_curve25519,
    sodium_crypto_sign_ed25519_pk_to_curve25519,
    sodium_crypto_sign_publickey_from_secretkey,
    sprintf;

/**
 * Class SignatureSecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class SignatureSecretKey extends SecretKey
{
    /**
     * SignatureSecretKey constructor.
     *
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws InvalidKey
     * @throws TypeError
     */
    public function __construct(
        #[\SensitiveParameter]
        HiddenString $keyMaterial,
        ?HiddenString $pk = null
    ) {
        if (Binary::safeStrlen($keyMaterial->getString()) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKey(
                sprintf(
                    'Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES (%d) bytes long',
                    SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
                )
            );
        }
        parent::__construct($keyMaterial, $pk);
        $this->isSigningKey = true;
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return SignaturePublicKey
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public function derivePublicKey(): SignaturePublicKey
    {
        if (is_null($this->cachedPublicKey)) {
            $this->cachedPublicKey = sodium_crypto_sign_publickey_from_secretkey(
                $this->getRawKeyMaterial()
            );
        }
        return new SignaturePublicKey(new HiddenString($this->cachedPublicKey));
    }

    /**
     * Get an encryption secret key from a signing secret key.
     *
     * @return EncryptionSecretKey
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public function getEncryptionSecretKey(): EncryptionSecretKey
    {
        $ed25519_sk = $this->getRawKeyMaterial();
        $x25519_sk = sodium_crypto_sign_ed25519_sk_to_curve25519(
            $ed25519_sk
        );
        if (!is_null($this->cachedPublicKey)) {
            $x25519_pk = sodium_crypto_sign_ed25519_pk_to_curve25519(
                $this->cachedPublicKey
            );
            return new EncryptionSecretKey(
                new HiddenString($x25519_sk),
                new HiddenString($x25519_pk)
            );
        }
        return new EncryptionSecretKey(
            new HiddenString($x25519_sk)
        );
    }
}
