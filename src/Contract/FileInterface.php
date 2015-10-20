<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Asymmetric\PublicKey;
use \ParagonIE\Halite\Asymmetric\SecretKey;
use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;

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
     * @param SymmetricKey $key
     */
    public static function encryptFile(
        $inputFile,
        $outputFile,
        SymmetricKey $key
    );
    
    /**
     * Decrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param SymmetricKey $key
     */
    public static function decryptFile(
        $inputFile,
        $outputFile,
        SymmetricKey $key
    );
    
    /**
     * Encrypt a file with a public key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param PublicKey $publickey
     */
    public static function sealFile(
        $inputFile,
        $outputFile,
        PublicKey $publickey
    );
    
    /**
     * Decrypt a file with a private key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param SecretKey $secretkey
     */
    public static function unsealFile(
        $inputFile,
        $outputFile,
        SecretKey $secretkey
    );
    
    /**
     * Encrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param SymmetricKey $key
     */
    public static function encryptResource(
        $input,
        $output,
        SymmetricKey $key
    );
    
    /**
     * Decrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param SymmetricKey $key
     */
    public static function decryptResource(
        $input,
        $output,
        SymmetricKey $key
    );
    
    /**
     * Seal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param PublicKey $publickey
     */
    public static function sealResource(
        $input,
        $output,
        PublicKey $publickey
    );
    
    /**
     * Unseal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param SecretKey $secretkey
     */
    public static function unsealResource(
        $input,
        $output,
        SecretKey $secretkey
    );
    
    
    /**
     * Calculate a checksum (derived from BLAKE2b) of a file
     * 
     * @param string $filepath The file you'd like to checksum
     * @param SymmetricKey $key An optional BLAKE2b key
     * @param bool $raw Set to true if you don't want hex
     * 
     * @return string
     */
    public static function checksumFile(
        $filepath,
        SymmetricKey $key = null,
        $raw = false
    );
    
    
    /**
     * Calculate a BLAHE2b checksum of a file
     * 
     * @param string $fileHandle The file you'd like to checksum
     * @param SymmetricKey $key An optional BLAKE2b key
     * @param bool $raw Set to true if you don't want hex
     * 
     * @return string
     */
    public static function checksumResource(
        $fileHandle,
        SymmetricKey $key = null,
        $raw = false
    );
}
