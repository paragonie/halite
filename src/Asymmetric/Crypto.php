<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts as CryptoException;
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
 * @package ParagonIE\Halite\Asymmetric
 */
final class Crypto
{
    /**
     * Encrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::encrypt()
     * 
     * @param HiddenString $plaintext              The message to encrypt
     * @param EncryptionSecretKey $ourPrivateKey   Our private key
     * @param EncryptionPublicKey $theirPublicKey  Their public key
     * @param mixed $encoding                      Which encoding scheme to use?
     * @return string                              Ciphertext
     */
    public static function encrypt(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        $sharedSecretKey = new EncryptionKey(
            self::getSharedSecret(
                $ourPrivateKey,
                $theirPublicKey
            )
        );
        $ciphertext = SymmetricCrypto::encrypt(
            $plaintext,
            $sharedSecretKey,
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
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        $sharedSecretKey = new EncryptionKey(
            self::getSharedSecret(
                $ourPrivateKey,
                $theirPublicKey
            )
        );
        $plaintext = SymmetricCrypto::decrypt(
            $ciphertext,
            $sharedSecretKey,
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
                    \Sodium\crypto_scalarmult(
                        $privateKey->getRawKeyMaterial(),
                        $publicKey->getRawKeyMaterial()
                    )
                )
            );
        }
        return new HiddenString(
            \Sodium\crypto_scalarmult(
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
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public static function seal(
        HiddenString $plaintext,
        EncryptionPublicKey $publicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        if (!$publicKey instanceof EncryptionPublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionPublicKey'
            );
        }
        if (!function_exists('\\Sodium\\crypto_box_seal')) {
            throw new CryptoException\CannotPerformOperation(
                'crypto_box_seal is not available'
            );
        }
        
        $sealed = \Sodium\crypto_box_seal(
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
        $signed = \Sodium\crypto_sign_detached(
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
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
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
                throw new CryptoException\InvalidMessage(
                    'Invalid character encoding'
                );
            }
        }

        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $privateKey->getRawKeyMaterial();
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        $key_pair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        
        // Wipe these immediately:
        \Sodium\memzero($secret_key);
        \Sodium\memzero($public_key);
        
        // Now let's open that sealed box
        $message = \Sodium\crypto_box_seal_open(
            $ciphertext,
            $key_pair
        );

        // Always memzero after retrieving a value
        \Sodium\memzero($key_pair);
        if ($message === false) {
            throw new CryptoException\InvalidKey(
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
     * @throws CryptoException\InvalidSignature
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
        if (CryptoUtil::safeStrlen($signature) !== \Sodium\CRYPTO_SIGN_BYTES) {
            throw new CryptoException\InvalidSignature(
                'Signature is not the correct length; is it encoded?'
            );
        }
        
        return \Sodium\crypto_sign_verify_detached(
            $signature,
            $message,
            $publicKey->getRawKeyMaterial()
        );
    }
}
