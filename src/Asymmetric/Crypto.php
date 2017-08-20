<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidKey,
    InvalidMessage,
    InvalidSignature
};
use ParagonIE\Halite\{
    Util as CryptoUtil,
    Halite,
    HiddenString,
    Key,
    Symmetric\Crypto as SymmetricCrypto,
    Symmetric\EncryptionKey
};

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
 */
final class Crypto
{
    /**
     * Don't allow this to be instantiated.
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
     * @param mixed $encoding                      Which encoding scheme to use?
     * @return string                              Ciphertext
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
     * @param string $encoding
     * @return string
     * @throws \TypeError
     */
    public static function encryptWithAd(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $additionalData = '',
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey
        );
        if (!($ss instanceof HiddenString)) {
            throw new \TypeError();
        }
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
     * @param mixed $encoding                     Which encoding scheme to use?
     * @return HiddenString                       The decrypted message
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
     *
     *
     * @param string $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $additionalData
     * @param string $encoding
     * @return HiddenString
     * @throws \TypeError
     */
    public static function decryptWithAd(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $additionalData = '',
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $ss = self::getSharedSecret(
            $ourPrivateKey,
            $theirPublicKey
        );
        if (!($ss instanceof HiddenString)) {
            throw new \TypeError();
        }
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
     * @param EncryptionSecretKey $privateKey
     * @param EncryptionPublicKey $publicKey
     * @param bool $get_as_object Get as a Key object?
     * @return HiddenString|Key
     */
    public static function getSharedSecret(
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $get_as_object = false
    ) {
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
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
            return $encoder($sealed);
        }
        return $sealed;
    }
    
    /**
     * Sign a message with our private key
     *
     * @param string $message Message to sign
     * @param SignatureSecretKey $privateKey
     * @param mixed $encoding Which encoding scheme to use?
     * @return string Signature (detached)
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
            return $encoder($signed);
        }
        return $signed;
    }
    
    /**
     * Decrypt a sealed message with our private key
     *
     * @param string $ciphertext Encrypted message
     * @param EncryptionSecretKey $privateKey
     * @param mixed $encoding Which encoding scheme to use?
     * @return HiddenString
     * @throws InvalidKey
     * @throws InvalidMessage
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
        if ($message === false) {
            throw new InvalidKey(
                'Incorrect secret key for this sealed message'
            );
        }

        // We have our encrypted message here
        return new HiddenString($message);
    }
    
    /**
     * Verify a signed message with the correct public key
     *
     * @param string $message Message to verify
     * @param SignaturePublicKey $publicKey
     * @param string $signature
     * @param mixed $encoding Which encoding scheme to use?
     * @return bool
     * @throws InvalidSignature
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
            $signature = $decoder($signature);
        }
        if (CryptoUtil::safeStrlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new InvalidSignature(
                'Signature is not the correct length; is it encoded?'
            );
        }
        
        return \sodium_crypto_sign_verify_detached(
            $signature,
            $message,
            $publicKey->getRawKeyMaterial()
        );
    }
}
