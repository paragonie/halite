<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Symmetric\{
    AuthenticationKey,
    EncryptionKey
};

/**
 * An interface fundamental to all cryptography implementations
 */
interface SymmetricKeyCryptoInterface
{    
    /**
     * Encrypt a message with a Key
     * 
     * @param string $plaintext
     * @param KeyInterface $secretKey
     * @param boolean $raw Don't hex encode the output?
     */
    public static function encrypt(
        string $plaintext,
        EncryptionKey $secretKey,
        bool $raw = false
    ): string;
    
    /**
     * Decrypt a message with a Key
     * 
     * @param string $ciphertext
     * @param KeyInterface $secretKey
     * @param boolean $raw Don't hex decode the input?
     */
    public static function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        bool $raw = false
    ): string;
    
    /**
     * Authenticate a message, get a message authentication code
     * 
     * @param string $message
     * @param KeyInterface $secretKey
     * @param boolean $raw
     */
    public static function authenticate(
        string $message,
        AuthenticationKey $secretKey,
        bool $raw = false
    ): string;
    
    /**
     * Verify the message authentication code
     * 
     * @param string $message
     * @param KeyInterface $secretKey
     * @param string $mac
     * @param boolean $raw
     */
    public static function verify(
        string $message,
        AuthenticationKey $secretKey,
        string $mac,
        bool $raw = false
    ): bool;
}
