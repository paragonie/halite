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
    Symmetric\EncryptionKey,
    Util
};
use ParagonIE\HiddenString\HiddenString;
use Error;
use RangeException;
use SodiumException;
use TypeError;
use const
    SODIUM_CRYPTO_STREAM_KEYBYTES,
    SODIUM_CRYPTO_SIGN_BYTES;
use function
    is_string,
    sodium_crypto_box_keypair_from_secretkey_and_publickey,
    sodium_crypto_box_publickey_from_secretkey,
    sodium_crypto_box_seal,
    sodium_crypto_box_seal_open,
    sodium_crypto_scalarmult,
    sodium_crypto_sign_detached,
    sodium_crypto_sign_verify_detached;

/**
 * Class Crypto
 *
 * Handles all public key cryptography
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 */
final class Crypto
{
    /**
     * Don't allow this to be instantiated.
     *
     * @throws Error
     * @codeCoverageIgnore
     */
    private function __construct()
    {
        throw new Error('Do not instantiate');
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
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encrypt(
        #[\SensitiveParameter]
        HiddenString $plaintext,
        #[\SensitiveParameter]
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return self::encryptWithAD(
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
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidDigestLength
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function encryptWithAD(
        #[\SensitiveParameter]
        HiddenString $plaintext,
        #[\SensitiveParameter]
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        #[\SensitiveParameter]
        string $additionalData = '',
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        /** @var HiddenString $ss */
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey,
            false,
            self::getAsymmetricConfig(Halite::HALITE_VERSION, true)
        );
        $sharedSecretKey = new EncryptionKey($ss);
        $ciphertext = SymmetricCrypto::encryptWithAD(
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
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decrypt(
        string $ciphertext,
        #[\SensitiveParameter]
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return self::decryptWithAD(
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
     *
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function decryptWithAD(
        string $ciphertext,
        #[\SensitiveParameter]
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        #[\SensitiveParameter]
        string $additionalData = '',
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        /** @var HiddenString $ss */
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey,
            false,
            self::getAsymmetricConfig($ciphertext, $encoding)
        );
        $sharedSecretKey = new EncryptionKey($ss);
        $plaintext = SymmetricCrypto::decryptWithAD(
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
     * @param ?Config $config                 Asymmetric Config
     *
     * @return HiddenString|Key
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws SodiumException
     * @throws TypeError
     */
    public static function getSharedSecret(
        #[\SensitiveParameter]
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $get_as_object = false,
        ?Config $config = null
    ): HiddenString|Key {
        if (!is_null($config)) {
            if ($config->HASH_SCALARMULT) {
                $hiddenString = new HiddenString(
                    Util::hkdfBlake2b(
                        sodium_crypto_scalarmult(
                            $privateKey->getRawKeyMaterial(),
                            $publicKey->getRawKeyMaterial()
                        ),
                        SODIUM_CRYPTO_STREAM_KEYBYTES,
                        (string) $config->HASH_DOMAIN_SEPARATION
                    )
                );
                if ($get_as_object) {
                    return new EncryptionKey($hiddenString);
                }
                return $hiddenString;
            }
        }

        $hiddenString = new HiddenString(
            sodium_crypto_scalarmult(
                $privateKey->getRawKeyMaterial(),
                $publicKey->getRawKeyMaterial()
            )
        );
        if ($get_as_object) {
            return new EncryptionKey($hiddenString);
        }
        return $hiddenString;
    }

    /**
     * Encrypt a message with a target users' public key
     *
     * @param HiddenString $plaintext        Message to encrypt
     * @param EncryptionPublicKey $publicKey Public encryption key
     * @param string|bool $encoding          Which encoding scheme to use?
     *
     * @return string                        Ciphertext
     *
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function seal(
        #[\SensitiveParameter]
        HiddenString $plaintext,
        EncryptionPublicKey $publicKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $sealed = sodium_crypto_box_seal(
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
     * @param string|bool $encoding          Which encoding scheme to use?
     *
     * @return string Signature (detached)
     *
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign(
        string $message,
        #[\SensitiveParameter]
        SignatureSecretKey $privateKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $signed = sodium_crypto_sign_detached(
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
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function signAndEncrypt(
        HiddenString $message,
        #[\SensitiveParameter]
        SignatureSecretKey $secretKey,
        PublicKey $recipientPublicKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
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
        Util::memzero($signature);

        $myEncKey = $secretKey->getEncryptionSecretKey();
        return self::encrypt($plaintext, $myEncKey, $publicKey, $encoding);
    }

    /**
     * Decrypt a sealed message with our private key
     *
     * @param string $ciphertext              Encrypted message
     * @param EncryptionSecretKey $privateKey Private decryption key
     * @param string|bool $encoding           Which encoding scheme to use?
     *
     * @return HiddenString
     *
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function unseal(
        string $ciphertext,
        #[\SensitiveParameter]
        EncryptionSecretKey $privateKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $decoder = Halite::chooseEncoder($encoding, true);
        if ($decoder) {
            // We were given hex data:
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (RangeException $ex) {
                throw new InvalidMessage(
                    'Invalid character encoding'
                );
            }
        }

        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $privateKey->getRawKeyMaterial();
        $public_key = sodium_crypto_box_publickey_from_secretkey($secret_key);
        $key_pair = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        
        // Wipe these immediately:
        Util::memzero($secret_key);
        Util::memzero($public_key);
        
        // Now let's open that sealed box
        $message = sodium_crypto_box_seal_open(
            $ciphertext,
            $key_pair
        );

        // Always memzero after retrieving a value
        Util::memzero($key_pair);
        if (!is_string($message)) {
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
     * @param string|bool $encoding         Which encoding scheme to use?
     *
     * @return bool
     *
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify(
        string $message,
        SignaturePublicKey $publicKey,
        string $signature,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
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
        
        return sodium_crypto_sign_verify_detached(
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
     *
     * @return HiddenString
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws InvalidKey
     * @throws InvalidMessage
     * @throws InvalidSignature
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verifyAndDecrypt(
        string $ciphertext,
        SignaturePublicKey $senderPublicKey,
        #[\SensitiveParameter]
        SecretKey $givenSecretKey,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
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

    /**
     * Get the Asymmetric configuration expected for this Halite version
     *
     * @param string $ciphertext
     * @param string|bool $encoding
     *
     * @return Config
     *
     * @throws InvalidMessage
     * @throws InvalidType
     */
    public static function getAsymmetricConfig(
        string $ciphertext,
        string|bool $encoding = Halite::ENCODE_BASE64URLSAFE
    ): Config {
        $decoder = Halite::chooseEncoder($encoding, true);
        if (is_callable($decoder)) {
            // We were given encoded data:
            // @codeCoverageIgnoreStart
            try {
                /** @var string $ciphertext */
                $ciphertext = $decoder($ciphertext);
            } catch (RangeException $ex) {
                throw new InvalidMessage(
                    'Invalid character encoding'
                );
            }
            // @codeCoverageIgnoreEnd
        }
        $version = Binary::safeSubstr(
            $ciphertext,
            0,
            Halite::VERSION_TAG_LEN
        );
        return Config::getConfig($version);
    }
}
