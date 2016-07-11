<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\{
    Util as CryptoUtil,
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
     * @param string $plaintext                    The message to encrypt
     * @param EncryptionSecretKey $ourPrivateKey   Our private key
     * @param EncryptionPublicKey $theirPublicKey  Their public key
     * @param bool $raw                            Don't hex encode the output
     * @return string                              Ciphertext
     */
    public static function encrypt(
        string $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        bool $raw = false
    ): string {
        $sharedSecretKey = new EncryptionKey(
            self::getSharedSecret($ourPrivateKey, $theirPublicKey)
        );
        $ciphertext = SymmetricCrypto::encrypt(
            $plaintext,
            $sharedSecretKey,
            $raw
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
     * @param bool $raw                           Expect raw binary
     * @return string                             The decrypted message
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        bool $raw = false
    ): string {
        $sharedSecretKey = new EncryptionKey(
            self::getSharedSecret($ourPrivateKey, $theirPublicKey)
        );
        $plaintext = SymmetricCrypto::decrypt($ciphertext, $sharedSecretKey, $raw);
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
     * @return string|Key
     */
    public static function getSharedSecret(
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $get_as_object = false
    ) {
        if ($get_as_object) {
            return new EncryptionKey(
                \Sodium\crypto_scalarmult(
                    $privateKey->getRawKeyMaterial(),
                    $publicKey->getRawKeyMaterial()
                )
            );
        }
        return \Sodium\crypto_scalarmult(
            $privateKey->getRawKeyMaterial(),
            $publicKey->getRawKeyMaterial()
        );
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string $plaintext              Message to encrypt
     * @param EncryptionPublicKey $publicKey Public encryption key
     * @param bool $raw                      Don't hex encode the output?
     * @return string                        Ciphertext
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public static function seal(
        string $plaintext,
        EncryptionPublicKey $publicKey,
        bool $raw = false
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
        
        $sealed = \Sodium\crypto_box_seal($plaintext, $publicKey->getRawKeyMaterial());
        if ($raw) {
            return $sealed;
        }
        return \Sodium\bin2hex($sealed);
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string $message Message to sign
     * @param SignatureSecretKey $privateKey
     * @param bool $raw Don't hex encode the output?
     * @return string Signature (detached)
     */
    public static function sign(
        string $message,
        SignatureSecretKey $privateKey,
        bool $raw = false
    ): string {
        $signed = \Sodium\crypto_sign_detached(
            $message,
            $privateKey->getRawKeyMaterial()
        );
        if ($raw) {
            return $signed;
        }
        return \Sodium\bin2hex($signed);
    }
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string $ciphertext Encrypted message
     * @param EncryptionSecretKey $privateKey
     * @param bool $raw Don't hex decode the input?
     * @return string
     * @throws CryptoException\InvalidKey
     */
    public static function unseal(
        string $ciphertext,
        EncryptionSecretKey $privateKey,
        bool $raw = false
    ): string {
        if (!$raw) {
            $ciphertext = \Sodium\hex2bin($ciphertext);
        }

        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $privateKey->getRawKeyMaterial();
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        $kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        
        // Wipe these immediately:
        \Sodium\memzero($secret_key);
        \Sodium\memzero($public_key);
        
        // Now let's open that sealed box
        $message = \Sodium\crypto_box_seal_open($ciphertext, $kp);

        // Always memzero after retrieving a value
        \Sodium\memzero($kp);
        if ($message === false) {
            throw new CryptoException\InvalidKey(
                'Incorrect secret key for this sealed message'
            );
        }

        // We have our encrypted message here
        return $message;
    }
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string $message Message to verify
     * @param SignaturePublicKey $publicKey
     * @param string $signature
     * @param bool $raw Don't hex decode the input?
     * @return bool
     * @throws CryptoException\InvalidSignature
     */
    public static function verify(
        string $message,
        SignaturePublicKey $publicKey,
        string $signature,
        bool $raw = false
    ): bool {
        if (!$raw) {
            $signature = \Sodium\hex2bin($signature);
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
