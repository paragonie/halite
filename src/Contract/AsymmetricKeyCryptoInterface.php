<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Contract;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;

/**
 * An interface fundamental to all cryptography implementations
 */
interface AsymmetricKeyCryptoInterface
{
    
    /**
     * Diffie-Hellman, ECDHE, etc.
     * 
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     * 
     * @param KeyInterface $privateKey
     * @param KeyInterface $publicKey
     * 
     * @return string
     */
    public static function getSharedSecret(
        KeyInterface $privateKey,
        KeyInterface $publicKey,
        bool $get_as_object = false
    );
    
    /**
     * Encrypt a string using asymmetric cryptography
     * Seal then sign
     * 
     * @param string $source Plaintext
     * @param EncryptionSecretKey $privatekey Our private key
     * @param EncryptionPublicKey $publickey Their public key
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function encrypt(
        string $source,
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $raw = false
    ): string;
    
    /**
     * Decrypt a string using asymmetric cryptography
     * Verify then unseal
     * 
     * @param string $source Ciphertext
     * @param EncryptionSecretKey $privatekey Our private key
     * @param EncryptionPublicKey $publickey Their public key
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function decrypt(
        string $source,
        EncryptionSecretKey $privateKey,
        EncryptionPublicKey $publicKey,
        bool $raw = false
    ): string;
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string $source Message to encrypt
     * @param EncryptionPublicKey $publicKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function seal(
        string $source,
        EncryptionPublicKey $publicKey,
        bool $raw = false
    ): string;
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string $source Encrypted message (string or resource for a file)
     * @param EncryptionSecretKey $privateKey
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function unseal(
        string $source,
        EncryptionSecretKey $privateKey,
        bool $raw = false
    ): string;
    
    /**
     * Sign a message with our private key
     * 
     * @param string $message Message to sign
     * @param SecretKey $privateKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string Signature (detached)
     */
    public static function sign(
        string $message,
        SignatureSecretKey $privateKey,
        bool $raw = false
    ): string;
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string $message Message to verifyn
     * @param PublicKey $publicKey
     * @param string $signature
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return boolean
     */
    public static function verify(
        string $message,
        SignaturePublicKey $publicKey,
        string $signature,
        bool $raw = false
    ): bool;
}
