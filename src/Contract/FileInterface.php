<?php
namespace ParagonIE\Halite\Contract;

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
    
    
    /**
     * Calculate a checksum (derived from BLAKE2b) of a file
     * 
     * @param string $filepath The file you'd like to checksum
     * @param string $key An optional BLAKE2b key
     * @param bool $raw Set to true if you don't want hex
     * 
     * @return string
     */
    public static function checksumFile(
        $filepath,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key = null,
        $raw = false
    );
    
    
    /**
     * Calculate a BLAHE2b checksum of a file
     * 
     * @param string $fileHandle The file you'd like to checksum
     * @param string $key An optional BLAKE2b key
     * @param bool $raw Set to true if you don't want hex
     * 
     * @return string
     */
    public static function checksumResource(
        $fileHandle,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $key = null,
        $raw = false
    );
}
