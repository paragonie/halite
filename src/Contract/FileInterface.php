<?php
namespace ParagonIE\Halite\Contract;

use \ParagonIE\Halite\Alerts as CryptoException;
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
     * Lazy fallthrough method for checksumFile() and checksumResource()
     *
     * @param string|resource $filepath
     * @param AuthenticationKey $key
     * @param bool $raw
     * @return string
     * @throws CryptoException\InvalidType
     */
    public static function checksum(
        $filepath,
        KeyInterface $key = null,
        $raw = false
    ): string;

    /**
     * Lazy fallthrough method for encryptFile() and encryptResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     * @return string
     * @throws CryptoException\InvalidType
     */
    public static function encrypt(
        $input,
        $output,
        EncryptionKey $key
    ): int;

    /**
     * Lazy fallthrough method for decryptFile() and decryptResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     * @return bool
     * @throws CryptoException\InvalidType
     */
    public static function decrypt(
        $input,
        $output,
        EncryptionKey $key
    ): bool;


    /**
     * Lazy fallthrough method for sealFile() and sealResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionPublicKey $publickey
     * @return int Number of bytes written
     * @throws Alerts\InvalidType
     */
    public static function seal(
        $input,
        $output,
        EncryptionPublicKey $publickey
    ): int;


    /**
     * Lazy fallthrough method for sealFile() and sealResource()
     *
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionSecretKey $secretkey
     * @return bool TRUE on success
     * @throws CryptoException\InvalidType
     */
    public static function unseal(
        $input,
        $output,
        EncryptionSecretKey $secretkey
    ): bool;


    /**
     * Lazy fallthrough method for signFile() and signResource()
     *
     * @param string|resource $filename
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary
     * @return string
     * @throws Alerts\InvalidType
     */
    public static function sign(
        $filename,
        SignatureSecretKey $secretkey,
        bool $raw_binary = false
    ): string;

    /**
     * Lazy fallthrough method for verifyFile() and verifyResource()
     *
     * @param string|resource $filename
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary
     *
     * @return string
     * @throws Alerts\InvalidType
     */
    public static function verify(
        $filename,
        SignaturePublicKey $publickey,
        string $signature,
        bool $raw_binary = false
    ): bool;
}
