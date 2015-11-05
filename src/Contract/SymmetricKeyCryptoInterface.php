<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

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
        $plaintext,
        KeyInterface $secretKey,
        $raw = false
    );
    
    /**
     * Decrypt a message with a Key
     * 
     * @param string $ciphertext
     * @param KeyInterface $secretKey
     * @param boolean $raw Don't hex decode the input?
     */
    public static function decrypt(
        $ciphertext,
        KeyInterface $secretKey,
        $raw = false
    );
    
    /**
     * Authenticate a message, get a message authentication code
     * 
     * @param string $message
     * @param KeyInterface $secretKey
     * @param boolean $raw
     */
    public static function authenticate(
        $message,
        KeyInterface $secretKey,
        $raw = false
    );
    
    /**
     * Verify the message authentication code
     * 
     * @param string $message
     * @param KeyInterface $secretKey
     * @param string $mac
     * @param boolean $raw
     */
    public static function verify(
        $message,
        KeyInterface $secretKey,
        $mac,
        $raw = false
    );
    
}
