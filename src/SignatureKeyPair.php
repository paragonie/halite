<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Asymmetric\{
    SignaturePublicKey,
    SignatureSecretKey
};
use ParagonIE\HiddenString\HiddenString;

/**
 * Class SignatureKeyPair
 *
 * Describes a pair of secret and public keys
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class SignatureKeyPair extends KeyPair
{
    /**
     * @var SignatureSecretKey
     */
    protected $secretKey;

    /**
     * @var SignaturePublicKey
     */
    protected $publicKey;

    /**
     * Pass it a secret key, it will automatically generate a public key
     *
     * @param array<int, Key> $keys
     *
     * @throws InvalidKey
     * @throws \TypeError
     */
    public function __construct(Key ...$keys)
    {
        switch (\count($keys)) {
            /**
             * If we received two keys, it must be an asymmetric secret key and
             * an asymmetric public key, in either order.
             */
            case 2:
                if (!$keys[0]->isAsymmetricKey() || !$keys[1]->isAsymmetricKey()) {
                    throw new InvalidKey(
                        'Only keys intended for asymmetric cryptography can be used in a KeyPair object'
                    );
                }
                if ($keys[0]->isPublicKey()) {
                    if ($keys[1]->isPublicKey()) {
                        throw new InvalidKey(
                            'Both keys cannot be public keys'
                        );
                    }
                    $this->setupKeyPair(
                        // @codeCoverageIgnoreStart
                        $keys[1] instanceof SignatureSecretKey
                            ? $keys[1]
                            : new SignatureSecretKey(
                                new HiddenString($keys[1]->getRawKeyMaterial())
                            )
                        // @codeCoverageIgnoreEnd
                    );
                } elseif ($keys[1]->isPublicKey()) {
                    $this->setupKeyPair(
                    // @codeCoverageIgnoreStart
                        $keys[0] instanceof SignatureSecretKey
                            ? $keys[0]
                            : new SignatureSecretKey(
                                new HiddenString($keys[0]->getRawKeyMaterial())
                            )
                    // @codeCoverageIgnoreEnd
                    );
                } else {
                    throw new InvalidKey(
                        'Both keys cannot be secret keys'
                    );
                }
                break;
            /**
             * If we only received one key, it must be an asymmetric secret key!
             */
            case 1:
                if (!$keys[0]->isAsymmetricKey()) {
                    throw new InvalidKey(
                        'Only keys intended for asymmetric cryptography can be used in a KeyPair object'
                    );
                }
                if ($keys[0]->isPublicKey()) {
                    // Ever heard of the Elliptic Curve Discrete Logarithm Problem?
                    throw new InvalidKey(
                        'We cannot generate a valid keypair given only a public key; we can given only a secret key, however.'
                    );
                }
                $this->setupKeyPair(
                // @codeCoverageIgnoreStart
                    $keys[0] instanceof SignatureSecretKey
                        ? $keys[0]
                        : new SignatureSecretKey(
                            new HiddenString($keys[0]->getRawKeyMaterial())
                        )
                // @codeCoverageIgnoreEnd
                );
                break;
            default:
                throw new \InvalidArgumentException(
                    'Halite\\EncryptionKeyPair expects 1 or 2 keys'
                );
        }
    }

    /**
     * @return EncryptionKeyPair
     * @throws InvalidKey
     * @throws \TypeError
     */
    public function getEncryptionKeyPair(): EncryptionKeyPair
    {
        return new EncryptionKeyPair(
            $this->secretKey->getEncryptionSecretKey(),
            $this->publicKey->getEncryptionPublicKey()
        );
    }

    /**
     * Set up our key pair
     *
     * @param SignatureSecretKey $secret
     * @return void
     *
     * @throws InvalidKey
     * @throws \TypeError
     */
    protected function setupKeyPair(SignatureSecretKey $secret): void
    {
        $this->secretKey = $secret;
        $this->publicKey = $this->secretKey->derivePublicKey();
    }

    /**
     * Get a Key object for the public key
     *
     * @return SignaturePublicKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * Get a Key object for the public key
     *
     * @return SignatureSecretKey
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }
}
