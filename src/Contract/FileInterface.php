<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Asymmetric\{
    EncryptionPublicKey,
    EncryptionSecretKey,
    SignaturePublicKey,
    SignatureSecretKey
};
use \ParagonIE\Halite\Symmetric\{
    AuthenticationKey,
    EncryptionKey
};

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
        string $inputFile,
        string $outputFile,
        EncryptionKey $key
    ): int;
    
    /**
     * Decrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param SymmetricKey $key
     */
    public static function decryptFile(
        string $inputFile,
        string $outputFile,
        EncryptionKey $key
    ): bool;
    
    /**
     * Encrypt a file with a public key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param PublicKey $publickey
     */
    public static function sealFile(
        string $inputFile,
        string $outputFile,
        EncryptionPublicKey $publickey
    ): int;
    
    /**
     * Decrypt a file with a private key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param SecretKey $secretkey
     */
    public static function unsealFile(
        string $inputFile,
        string $outputFile,
        EncryptionSecretKey $secretkey
    ): bool;

    /**
     * Signs a file
     *
     * @param string $filename
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary
     *
     * @return string
     */
    public static function signFile(
        string $filename,
        SignatureSecretKey $secretkey,
        bool $raw_binary = false
    ): string;

    /**
     * Verifies a file
     *
     * @param string $filename
     * @param SignaturePublicKey $publickey
     * @param string $signature
     */
    public static function verifyFile(
        string $filename,
        SignaturePublicKey $publickey,
        string $signature,
        bool $raw_binary = false
    ): bool;

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
    ): int;
    
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
    ): bool;
    
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
    ): int;
    
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
    ): bool;

    /**
     * Signs a file
     *
     * @param string $input
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary
     *
     * @return string
     */
    public static function signResource(
        $input,
        SignatureSecretKey $secretkey,
        bool $raw_binary = false
    ): string;

    /**
     * Verifies a file
     *
     * @param string $input
     * @param SignaturePublicKey $publickey
     * @param string $signature
     *
     * @return bool
     */
    public static function verifyResource(
        $input,
        SignaturePublicKey $publickey,
        string $signature,
        bool $raw_binary = false
    ): bool;
    
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
        string $filepath,
        Key $key = null,
        bool $raw = false
    ): string;
    
    
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
        Key $key = null,
        bool $raw = false
    ): string;
}
