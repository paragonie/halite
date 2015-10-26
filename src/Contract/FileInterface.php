<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Asymmetric\PublicKey;
use \ParagonIE\Halite\Asymmetric\SecretKey;
use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

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
        EncryptionKey $key
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
        EncryptionKey $key
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
        EncryptionPublicKey $publickey
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
        EncryptionSecretKey $secretkey
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
        EncryptionKey $key
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
        EncryptionKey $key
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
        EncryptionPublicKey $publickey
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
        EncryptionSecretKey $secretkey
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
        AuthenticationKey $key = null,
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
        AuthenticationKey $key = null,
        $raw = false
    );
}
