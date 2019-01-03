<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    InvalidType
};
use ParagonIE\Halite\{
    Halite,
    Key,
    Symmetric\Crypto as SymmetricCrypto,
    Symmetric\EncryptionKey
};
use ParagonIE\HiddenString\HiddenString;

/**
 * Class Crypto
 *
 * Handles all public key cryptography
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class Crypto
{
    /**
     * Don't allow this to be instantiated.
     *
     * @throws \Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Encrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::encrypt()
     *
     * @param HiddenString $plaintext              The message to encrypt
     * @param EncryptionSecretKey $ourPrivateKey   Our private key
     * @param EncryptionPublicKey $theirPublicKey  Their public key
     * @param string|bool $encoding                Which encoding scheme to use?
     * @return string                              Ciphertext
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidDigestLength
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function encrypt(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return static::encryptWithAd(
            $plaintext,
            $ourPrivateKey,
            $theirPublicKey,
            '',
            $encoding
        );
    }

    /**
     * Encrypt with additional associated data.
     *
     * @param HiddenString $plaintext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $additionalData
     * @param string|bool $encoding
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidDigestLength
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function encryptWithAd(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $additionalData = '',
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        /** @var HiddenString $ss */
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey
        );
        $sharedSecretKey = new EncryptionKey($ss);
        $ciphertext = SymmetricCrypto::encryptWithAd(
            $plaintext,
            $sharedSecretKey,
            $additionalData,
            $encoding
        );
        unset($sharedSecretKey);
        return $ciphertext;
    }

    /**
     * Decrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::decrypt()
     *
     * @param string $ciphertext                  The message to decrypt
     * @param EncryptionSecretKey $ourPrivateKey  Our private key
     * @param EncryptionPublicKey $theirPublicKey Their public key
     * @param string|bool $encoding               Which encoding scheme to use?
     * @return HiddenString                       The decrypted message
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return static::decryptWithAd(
            $ciphertext,
            $ourPrivateKey,
            $theirPublicKey,
            '',
            $encoding
        );
    }

    /**
     * Decrypt with additional associated data.
     *
     * @param string $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $additionalData
     * @param string|bool $encoding
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function decryptWithAd(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $additionalData = '',
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        /** @var HiddenString $ss */
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey
        );
        $sharedSecretKey = new EncryptionKey($ss);
        $plaintext = SymmetricCrypto::decryptWithAd(
            $ciphertext,
            $sharedSecretKey,
            $additionalData,
            $encoding
        );
        unset($sharedSecretKey);
        return $plaintext;
    }

    /**
     * Diffie-Hellman, ECDHE, etc.
     *
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     *
     * @param EncryptionSecretKey $privateKey Private key (yours)
     * @param EncryptionPublicKey $publicKey  Public key (theirs)
     * @param bool $get_as_object             Get as a Key object?
     * @return HiddenString|Key
     *
     * @throws InvalidKey
     * @throws \TypeError
     */
    public static function getSharedSecret(
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $get_as_object = false
    ): object {
        if ($get_as_object) {
            return new EncryptionKey(
                new HiddenString(
                    \sodium_crypto_scalarmult(
                        $privateKey->getRawKeyMaterial(),
                        $publicKey->getRawKeyMaterial()
                    )
                )
            );
        }
        return new HiddenString(
            \sodium_crypto_scalarmult(
                $privateKey->getRawKeyMaterial(),
                $publicKey->getRawKeyMaterial()
            )
        );
    }

    /**
     * Encrypt a message with a target users' public key
     *
     * @param HiddenString $plaintext        Message to encrypt
     * @param EncryptionPublicKey $publicKey Public encryption key
     * @param mixed $encoding                Which encoding scheme to use?
     * @return string                        Ciphertext
     *
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function seal(
        HiddenString $plaintext,
        EncryptionPublicKey $publicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $sealed = \sodium_crypto_box_seal(
            $plaintext->getString(),
            $publicKey->getRawKeyMaterial()
        );
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return (string) $encoder($sealed);
        }
        return (string) $sealed;
    }

    /**
     * Sign a message with our private key
     *
     * @param string $message                Message to sign
     * @param SignatureSecretKey $privateKey Private signing key
     * @param mixed $encoding                Which encoding scheme to use?
     * @return string Signature (detached)
     *
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function sign(
        string $message,
        SignatureSecretKey $privateKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $signed = \sodium_crypto_sign_detached(
            $message,
            $privateKey->getRawKeyMaterial()
        );
        $encoder = Halite::chooseEncoder($encoding);
        if ($encoder) {
            return (string) $encoder($signed);
        }
        return (string) $signed;
    }

    /**
     * Sign a message then encrypt it with the recipient's public key.
     *
     * @param HiddenString $message           Plaintext message to sign and encrypt
     * @param SignatureSecretKey $secretKey   Private signing key
     * @param PublicKey $recipientPublicKey   Public encryption key
     * @param string|bool $encoding           Which encoding scheme to use?
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function signAndEncrypt(
        HiddenString $message,
        SignatureSecretKey $secretKey,
        PublicKey $recipientPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        if ($recipientPublicKey instanceof SignaturePublicKey) {
            $publicKey = $recipientPublicKey->getEncryptionPublicKey();
        } elseif ($recipientPublicKey instanceof EncryptionPublicKey) {
            $publicKey = $recipientPublicKey;
        } else {
            // @codeCoverageIgnoreStart
            throw new InvalidKey('An invalid key type was provided');
            // @codeCoverageIgnoreEnd
        }
        $signature = self::sign($message->getString(), $secretKey, true);
        $plaintext = new HiddenString($signature . $message->getString());
        \sodium_memzero($signature);

        $myEncKey = $secretKey->getEncryptionSecretKey();
        return self::encrypt($plaintext, $myEncKey, $publicKey, $encoding);
    }

    /**
     * Decrypt a sealed message with our private key
     *
     * @param string $ciphertext              Encrypted message
     * @param EncryptionSecretKey $privateKey Private decryption key
     * @param mixed $encoding                 Which encoding scheme to use?
     * @return HiddenString
     *
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function unseal(
        string $ciphertext,
        EncryptionSecretKey $privateKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (\RangeException $ex) {
                throw new InvalidMessage(
                    'Invalid character encoding'
                );
            }
        }

        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $privateKey->getRawKeyMaterial();
        $public_key = \sodium_crypto_box_publickey_from_secretkey($secret_key);
        $key_pair = \sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        
        // Wipe these immediately:
        \sodium_memzero($secret_key);
        \sodium_memzero($public_key);
        
        // Now let's open that sealed box
        $message = \sodium_crypto_box_seal_open(
            $ciphertext,
            $key_pair
        );

        // Always memzero after retrieving a value
        \sodium_memzero($key_pair);
        if (!\is_string($message)) {
            // @codeCoverageIgnoreStart
            throw new InvalidKey(
                'Incorrect secret key for this sealed message'
            );
            // @codeCoverageIgnoreEnd
        }

        // We have our encrypted message here
        return new HiddenString($message);
    }

    /**
     * Verify a signed message with the correct public key
     *
     * @param string $message               Message to verify
     * @param SignaturePublicKey $publicKey Public key
     * @param string $signature             Signature
     * @param mixed $encoding               Which encoding scheme to use?
     * @return bool
     *
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function verify(
        string $message,
        SignaturePublicKey $publicKey,
        string $signature,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): bool {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            /** @var string $signature */
            $signature = $decoder($signature);
        }
        if (Binary::safeStrlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            // @codeCoverageIgnoreStart
            throw new InvalidSignature(
                'Signature is not the correct length; is it encoded?'
            );
            // @codeCoverageIgnoreEnd
        }
        
        return (bool) \sodium_crypto_sign_verify_detached(
            $signature,
            $message,
            $publicKey->getRawKeyMaterial()
        );
    }

    /**
     * Decrypt a message, then verify its signature.
     *
     * @param string $ciphertext                   Plaintext message to sign and encrypt
     * @param SignaturePublicKey $senderPublicKey  Private signing key
     * @param SecretKey $givenSecretKey            Public encryption key
     * @param string|bool $encoding                Which encoding scheme to use?
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws \TypeError
     */
    public static function verifyAndDecrypt(
        string $ciphertext,
        SignaturePublicKey $senderPublicKey,
        SecretKey $givenSecretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        if ($givenSecretKey instanceof SignatureSecretKey) {
            $secretKey = $givenSecretKey->getEncryptionSecretKey();
        } elseif ($givenSecretKey instanceof EncryptionSecretKey) {
            $secretKey = $givenSecretKey;
        } else {
            throw new InvalidKey('An invalid key type was provided');
        }
        $senderEncKey = $senderPublicKey->getEncryptionPublicKey();
        $decrypted = self::decrypt($ciphertext, $secretKey, $senderEncKey, $encoding);
        $signature = Binary::safeSubstr($decrypted->getString(), 0, SODIUM_CRYPTO_SIGN_BYTES);
        $message = Binary::safeSubstr($decrypted->getString(), SODIUM_CRYPTO_SIGN_BYTES);
        if (!self::verify($message, $senderPublicKey, $signature, true)) {
            throw new InvalidSignature('Invalid signature for decrypted message');
        }
        return new HiddenString($message);
    }
}
