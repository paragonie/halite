<?php
namespace ParagonIE\Halite\Contract\Crypto;

/**
 * An interface for encrypting/decrypting files
 */
interface FileInterface 
{
    /**
     * Encrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $key
     */
    public static function encryptFile(
        $inputFile,
        $outputFile,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key
    );
    
    /**
     * Decrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $key
     */
    public static function decryptFile(
        $inputFile,
        $outputFile,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key
    );
    
    /**
     * Encrypt a file with a public key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
     */
    public static function sealFile(
        $inputFile,
        $outputFile,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
    );
    
    /**
     * Decrypt a file with a private key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
     */
    public static function unsealFile(
        $inputFile,
        $outputFile,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
    );
    
    /**
     * Encrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $key
     */
    public static function encryptResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key
    );
    
    /**
     * Decrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $key
     */
    public static function decryptResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key
    );
    
    /**
     * Seal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
     */
    public static function sealResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
    );
    
    /**
     * Unseal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
     */
    public static function unsealResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
    );
}
