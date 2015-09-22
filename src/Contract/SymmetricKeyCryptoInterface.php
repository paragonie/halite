<?php
namespace ParagonIE\Halite\Contract;

/**
 * An interface fundamental to all cryptography implementations
 */
interface SymmetricKeyCryptoInterface extends CryptoInterface
{    
    /**
     * Encrypt a message with a Key
     * 
     * @param string $plaintext
     * @param CryptoKeyInterface $secretKey
     * @param boolean $raw Don't hex encode the output?
     */
    public static function encrypt(
        $plaintext, 
        CryptoKeyInterface $secretKey,
        $raw = false
    );
    
    /**
     * Decrypt a message with a Key
     * 
     * @param string $ciphertext
     * @param CryptoKeyInterface $secretKey
     * @param boolean $raw Don't hex decode the input?
     */
    public static function decrypt(
        $ciphertext,
        CryptoKeyInterface $secretKey,
        $raw = false
    );
}
