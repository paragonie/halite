<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;
use \ParagonIE\Halite\Config;
use \ParagonIE\Halite\Contract\KeyInterface;
use \ParagonIE\Halite\Contract\StreamInterface;
use \ParagonIE\Halite\Halite;
use \ParagonIE\Halite\Util;
use \ParagonIE\Halite\Stream\MutableFile;
use \ParagonIE\Halite\Stream\ReadOnlyFile;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

final class File implements \ParagonIE\Halite\Contract\FileInterface
{
    /**
     * Lazy fallthrough method for checksumFile() and checksumResource()
     * 
     * @param string|resource $filepath
     * @param AuthenticationKey $key
     * @param bool $raw
     */
    public static function checksum(
        $filepath,
        KeyInterface $key = null,
        $raw = false
    ) {
        if (\is_resource($filepath) || \is_string($filepath)) {
            return self::checksumStream(
                new ReadOnlyFile($filepath),
                $key,
                $raw
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
    /**
     * Lazy fallthrough method for encryptFile() and encryptResource()
     * 
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     */
    public static function encrypt(
        $input,
        $output,
        KeyInterface $key
    ) {
        if (
            \is_resource($input) ||
            \is_resource($output) ||
            \is_string($input) ||
            \is_string($output)
        ) {
            return self::encryptStream(
                new ReadOnlyFile($input),
                new MutableFile($output),
                $key
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
    /**
     * Lazy fallthrough method for decryptFile() and decryptResource()
     * 
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionKey $key
     */
    public static function decrypt(
        $input,
        $output,
        KeyInterface $key
    ) {
        if (
            \is_resource($input) ||
            \is_resource($output) ||
            \is_string($input) ||
            \is_string($output)
        ) {
            return self::decryptStream(
                new ReadOnlyFile($input),
                new MutableFile($output),
                $key
            );
        }
        throw new \InvalidArgumentException(
            'Strings or file handles expected'
        );
    }
    
    /**
     * Lazy fallthrough method for sealFile() and sealResource()
     * 
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionPublicKey $publickey
     */
    public static function seal(
        $input,
        $output,
        KeyInterface $publickey
    ) {
        if (
            \is_resource($input) ||
            \is_resource($output) ||
            \is_string($input) ||
            \is_string($output)
        ) {
            return self::sealStream(
                new ReadOnlyFile($input),
                new MutableFile($output),
                $publickey
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
    /**
     * Lazy fallthrough method for sealFile() and sealResource()
     * 
     * @param string|resource $input
     * @param string|resource $output
     * @param EncryptionSecretKey $secretkey
     */
    public static function unseal(
        $input,
        $output,
        KeyInterface $secretkey
    ) {
        if (
            \is_resource($input) ||
            \is_resource($output) ||
            \is_string($input) ||
            \is_string($output)
        ) {
            return self::unsealStream(
                new ReadOnlyFile($input),
                new MutableFile($output),
                $secretkey
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
    /**
     * Lazy fallthrough method for signFile() and signResource()
     * 
     * @param string|resource $filename
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary
     * 
     * @return string
     */
    public static function sign(
        $filename,
        KeyInterface $secretkey,
        $raw_binary = false
    ) {
        
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            return self::signStream(
                new ReadOnlyFile($filename),
                $secretkey,
                $raw_binary
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
    /**
     * Lazy fallthrough method for verifyFile() and verifyResource()
     * 
     * @param string|resource $filename
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary
     * 
     * @return string
     */
    public static function verify(
        $filename,
        KeyInterface $publickey,
        $signature,
        $raw_binary = false
    ) {
        if (
            \is_resource($filename) ||
            \is_string($filename)
        ) {
            return self::verifyStream(
                new ReadOnlyFile($filename),
                $publickey,
                $signature,
                $raw_binary
            );
        }
        throw new \ParagonIE\Halite\Alerts\InvalidType(
            'Argument 1: Expected a filename or resource'
        );
    }
    
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
        KeyInterface $key = null,
        $raw = false
    ) {
        if (!is_readable($filepath)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read the file'
            );
        }
        $fp = \fopen($filepath, 'rb');
        if ($fp === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read the file'
            );
        }
        try {
            $checksum = self::checksumResource($fp, $key, $raw);
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($fp);
            throw $e;
        }
        \fclose($fp);
        return $checksum;
    }
    
    
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
        KeyInterface $key = null,
        $raw = false
    ) {
        // Input validation
        if (!\is_resource($fileHandle)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        
        return self::checksumStream(
            new ReadOnlyFile($fileHandle),
            $key,
            $raw
        );
    }
    /**
     * 
     * @param \ParagonIE\Halite\Contract\StreamInterface $fileStream
     * @param AuthenticationKey $key
     * @param type $raw
     * @return type
     */
    public static function checksumStream(
        StreamInterface $fileStream,
        KeyInterface $key = null,
        $raw = false
    ) {
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'checksum');
        if ($key instanceof AuthenticationKey) {
            $state = \Sodium\crypto_generichash_init($key->get(), $config->HASH_LEN);
        } elseif($config->CHECKSUM_PUBKEY && $key instanceof SignaturePublicKey) {
            // In version 2, we use the public key as a hash key
            $state = \Sodium\crypto_generichash_init($key->get(), $config->HASH_LEN);
        } elseif (isset($key)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 2: Expected an instance of AuthenticationKey'
            );
        } else {
            $state = \Sodium\crypto_generichash_init(null, $config->HASH_LEN);
        }
        $size = $fileStream->getSize();
        while ($fileStream->remainingBytes() > 0) {
            $read = $fileStream->readBytes(
                ($fileStream->getPos() + $config->BUFFER) > $size
                    ? ($size - $fileStream->getPos())
                    : $config->BUFFER
            );
            \Sodium\crypto_generichash_update($state, $read);
        }
        if ($raw) {
            return \Sodium\crypto_generichash_final($state, $config->HASH_LEN);
        }
        return \Sodium\bin2hex(
            \Sodium\crypto_generichash_final($state, $config->HASH_LEN)
        );
    }

    /**
     * Encrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param EncryptionKey $key
     */
    public static function encryptFile(
        $inputFile,
        $outputFile,
        KeyInterface $key
    ) {
        if (!\is_readable($inputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        if (!\is_writable($outputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $inputHandle = \fopen($inputFile, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $outputHandle = \fopen($outputFile, 'wb');
        if ($outputHandle === false) {
            \fclose($inputHandle);
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        try {
            $result = self::encryptResource(
                $inputHandle,
                $outputHandle,
                $key
            );

            \fclose($inputHandle);
            \fclose($outputHandle);
            return $result;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            \fclose($outputHandle);
            
            // Rethrow the exception:
            throw $e;
        }
    }
    
    /**
     * Decrypt a file with a symmetric key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param EncryptionKey $key
     */
    public static function decryptFile(
        $inputFile,
        $outputFile,
        KeyInterface $key
    ) {
        if (!\is_readable($inputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        if (!\is_writable($outputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $inputHandle = \fopen($inputFile, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $outputHandle = \fopen($outputFile, 'wb');
        if ($outputHandle === false) {
            \fclose($inputHandle);
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        try {
            $result = self::decryptResource(
                $inputHandle,
                $outputHandle,
                $key
            );

            \fclose($inputHandle);
            \fclose($outputHandle);
            return $result;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            \fclose($outputHandle);
            
            // Rethrow the exception:
            throw $e;
        }
    }
    
    /**
     * Encrypt a file with a public key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param EncryptionPublicKey $publickey
     */
    public static function sealFile(
        $inputFile,
        $outputFile,
        KeyInterface $publickey
    ) {
        
        if (!\is_readable($inputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        if (!\is_writable($outputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $inputHandle = \fopen($inputFile, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $outputHandle = \fopen($outputFile, 'wb');
        if ($outputHandle === false) {
            \fclose($inputHandle);
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        try {
            $return = self::sealResource(
                $inputHandle,
                $outputHandle,
                $publickey
            );

            \fclose($inputHandle);
            \fclose($outputHandle);
            return $return;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            \fclose($outputHandle);
            
            // Rethrow the exception:
            throw $e;
        }
    }
    
    /**
     * Decrypt a file with a private key
     * 
     * @param string $inputFile
     * @param string $outputFile
     * @param EncryptionSecretKey $secretkey
     */
    public static function unsealFile(
        $inputFile,
        $outputFile,
        KeyInterface $secretkey
    ) {
        if (!\is_readable($inputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        if (!\is_writable($outputFile)) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $inputHandle = \fopen($inputFile, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $outputHandle = \fopen($outputFile, 'wb');
        if ($outputHandle === false) {
            \fclose($inputHandle);
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        try {
            $return = self::unsealResource(
                $inputHandle,
                $outputHandle,
                $secretkey
            );
            
            \fclose($inputHandle);
            \fclose($outputHandle);
            return $return;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            \fclose($outputHandle);
            
            // Rethrow the exception:
            throw $e;
        }
    }
    
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
        $filename,
        KeyInterface $secretkey,
        $raw_binary = false
    ) {
        
        if (!\is_readable($filename)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $inputHandle = \fopen($filename, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        
        try {
            $return = self::signResource(
                $inputHandle,
                $secretkey,
                $raw_binary
            );

            \fclose($inputHandle);
            return $return;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            // Rethrow the exception:
            throw $e;
        }
    }
    
    /**
     * Verifies a file
     * 
     * @param string $filename
     * @param SignaturePublicKey $publickey
     * @param string $signature
     */
    public static function verifyFile(
        $filename,
        KeyInterface $publickey,
        $signature,
        $raw_binary = false
    ) {
        
        if (!\is_readable($filename)) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        $inputHandle = \fopen($filename, 'rb');
        if ($inputHandle === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not read from the file'
            );
        }
        
        try {
            $return = self::verifyResource(
                $inputHandle,
                $publickey,
                $signature,
                $raw_binary
            );

            \fclose($inputHandle);
            return $return;
        } catch (CryptoException\HaliteAlert $e) {
            \fclose($inputHandle);
            // Rethrow the exception:
            throw $e;
        }
    }
    
    /**
     * Encrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     */
    public static function encryptResource(
        $input,
        $output,
        KeyInterface $key
    ) {
        // Input validation
        if (!\is_resource($input)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        if (!\is_resource($output)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected output handle to be a resource'
            );
        }
        return self::encryptStream(
            new ReadOnlyFile($input),
            new MutableFile($output),
            $key
        );
    }
    
    /**
     * Encrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     */
    public static function encryptStream(
        ReadOnlyFile $input,
        MutableFile $output,
        KeyInterface $key
    ) {
        if (!($key instanceof EncryptionKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionKey'
            );
        }
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'encrypt');
        
        // Generate a nonce and HKDF salt
        $firstnonce = \Sodium\randombytes_buf($config->NONCE_BYTES);
        $hkdfsalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);
        
        // Let's split our key
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        // We no longer need $authKey after we set up the hash context
        unset($authKey);
        
        // Write the header
        $output->writeBytes(Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        $output->writeBytes($firstnonce, \Sodium\CRYPTO_STREAM_NONCEBYTES);
        $output->writeBytes($hkdfsalt, $config->HKDF_SALT_LEN);
        
        \hash_update($mac, Halite::HALITE_VERSION_FILE);
        \hash_update($mac, $firstnonce);
        \hash_update($mac, $hkdfsalt);
        
        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $firstnonce,
            $mac,
            $config
        );
    }
    
    /**
     * Decrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     */
    public static function decryptResource(
        $input,
        $output,
        KeyInterface $key
    ) {
        // Input validation
        if (!\is_resource($input)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        if (!\is_resource($output)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected output handle to be a resource'
            );
        }
        return self::decryptStream(
            new ReadOnlyFile($input),
            new MutableFile($output),
            $key
        );
    }
    
    /**
     * Decrypt a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionKey $key
     */
    public static function decryptStream(
        ReadOnlyFile $input,
        MutableFile $output,
        KeyInterface $key
    ) {
        if (!($key instanceof EncryptionKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionKey'
            );
        }
        $input->reset(0);
        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);
        
        // Load the config
        $config = self::getConfig($header, 'encrypt');
        
        // Let's grab the first nonce and salt
        $firstnonce = $input->readBytes($config->NONCE_BYTES);
        $hkdfsalt = $input->readBytes($config->HKDF_SALT_LEN);
        
        // Split our keys, begin the HMAC instance
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        
        \hash_update($mac, $header);
        \hash_update($mac, $firstnonce);
        \hash_update($mac, $hkdfsalt);
        
        // This will throw an exception if it fails.
        $old_macs = self::streamVerify($input, \hash_copy($mac), $config);
        
        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $firstnonce,
            $mac,
            $config,
            $old_macs
        );
        
        unset($encKey);
        unset($authKey);
        unset($firstnonce);
        unset($mac);
        unset($config);
        unset($old_macs);
        return $ret;
    }
    
    /**
     * Seal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionPublicKey $publickey
     */
    public static function sealResource(
        $input,
        $output,
        KeyInterface $publickey
    ) {
        // Input validation
        if (!\is_resource($input)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        if (!\is_resource($output)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected output handle to be a resource'
            );
        }
        return self::sealStream(
            new ReadOnlyFile($input),
            new MutableFile($output),
            $publickey
        );
    }
    
    /**
     * Seal a (file handle)
     * 
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionPublicKey $publickey
     */
    public static function sealStream(
        ReadOnlyFile $input,
        MutableFile $output,
        KeyInterface $publickey
    ) {
        if (!($publickey instanceof EncryptionPublicKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionPublicKey'
            );
        }
        // Generate a new keypair for this encryption
        $eph_kp = KeyFactory::generateEncryptionKeyPair();
            $eph_secret = $eph_kp->getSecretKey();
            $eph_public = $eph_kp->getPublicKey();
        unset($eph_kp);
        
        // Calculate the shared secret key
        $key = AsymmetricCrypto::getSharedSecret($eph_secret, $publickey, true);
        
        // Destroy the secre tkey after we have the shared secret
        unset($eph_secret);
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'seal');
        
        // Generate a nonce as per crypto_box_seal
        $nonce = \Sodium\crypto_generichash(
            $eph_public->get().$publickey->get(),
            null,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        // Generate a random HKDF salt
        $hkdfsalt = \Sodium\randombytes_buf($config->HKDF_SALT_LEN);
        
        // Split the keys
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);
        
        // We no longer need the original key after we split it
        unset($key);
        
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        // We no longer need to retain this after we've set up the hash context
        unset($authKey);
        
        $output->writeBytes(Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        $output->writeBytes($eph_public->get(), \Sodium\CRYPTO_BOX_PUBLICKEYBYTES);
        $output->writeBytes($hkdfsalt, $config->HKDF_SALT_LEN);
        
        \hash_update($mac, Halite::HALITE_VERSION_FILE);
        \hash_update($mac, $eph_public->get());
        \hash_update($mac, $hkdfsalt);
        
        unset($eph_public);
        
        return self::streamEncrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $nonce,
            $mac,
            $config
        );
    }
    
    /**
     * Unseal a (file handle)
     * 
     * @param $input
     * @param $output
     * @param EncryptionSecretKey $secretkey
     */
    public static function unsealResource(
        $input,
        $output,
        KeyInterface $secretkey
    ) {
        // Input validation
        if (!\is_resource($input)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        if (!\is_resource($output)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected output handle to be a resource'
            );
        }
        return self::unsealStream(
            new ReadOnlyFile($input),
            new MutableFile($output),
            $secretkey
        );
    }
    
    /**
     * Unseal a (file handle)
     * 
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionSecretKey $secretkey
     */
    public static function unsealStream(
        ReadOnlyFile $input,
        MutableFile $output,
        EncryptionSecretKey $secretkey
    ) {
        if (!($secretkey instanceof EncryptionSecretKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionSecretKey'
            );
        }
        $secret_key = $secretkey->get();
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        
        // Parse the header, ensuring we get 4 bytes
        $header = $input->readBytes(Halite::VERSION_TAG_LEN);
        // Load the config
        $config = self::getConfig($header, 'seal');
        // Let's grab the public key and salt
        $eph_public = $input->readBytes($config->PUBLICKEY_BYTES);
        $hkdfsalt = $input->readBytes($config->HKDF_SALT_LEN);
        
        $nonce = \Sodium\crypto_generichash(
            $eph_public . $public_key,
            null,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        $ephemeral = new EncryptionPublicKey($eph_public);
        
        $key = AsymmetricCrypto::getSharedSecret(
            $secretkey, 
            $ephemeral,
            true
        );
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt, $config);
        // We no longer need the original key after we split it
        unset($key);
        
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        
        \hash_update($mac, $header);
        \hash_update($mac, $eph_public);
        \hash_update($mac, $hkdfsalt);
        
        // This will throw an exception if it fails.
        $old_macs = self::streamVerify($input, \hash_copy($mac), $config);
        
        $ret = self::streamDecrypt(
            $input,
            $output,
            new EncryptionKey($encKey),
            $nonce,
            $mac,
            $config,
            $old_macs
        );
        
        unset($encKey);
        unset($authKey);
        unset($nonce);
        unset($mac);
        unset($config);
        unset($old_macs);
        return $ret;
    }
    
    /**
     * Sign the contents of a file
     * 
     * @param $input (file handle)
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary Don't hex encode?
     */
    public static function signResource(
        $input,
        KeyInterface $secretkey,
        $raw_binary = false
    ) {
        return self::signStream(
            new ReadOnlyFile($input),
            $secretkey,
            $raw_binary
        );
    }
    
    /**
     * Sign the contents of a file
     * 
     * @param ReadOnlyFile $input
     * @param SignatureSecretKey $secretkey
     * @param bool $raw_binary Don't hex encode?
     */
    public static function signStream(
        ReadOnlyFile $input,
        KeyInterface $secretkey,
        $raw_binary = false
    ) {
        if (!($secretkey instanceof SignatureSecretKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 1: Expected an instance of SignatureSecretKey'
            );
        }
        $csum = self::checksumStream($input, $secretkey->derivePublicKey(), true);
        return AsymmetricCrypto::sign($csum, $secretkey, $raw_binary);
    }
    
    /**
     * Verify the contents of a file
     * 
     * @param $input (file handle)
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary Don't hex encode?
     * 
     * @return bool
     */
    public static function verifyResource(
        $input,
        KeyInterface $publickey,
        $signature,
        $raw_binary = false
    ) {
        return self::verifyStream(
            new ReadOnlyFile($input),
            $publickey,
            $signature,
            $raw_binary
        );
    }
    
    
    /**
     * Verify the contents of a file
     * 
     * @param $input (file handle)
     * @param SignaturePublicKey $publickey
     * @param string $signature
     * @param bool $raw_binary Don't hex encode?
     * 
     * @return bool
     */
    public static function verifyStream(
        ReadOnlyFile $input,
        KeyInterface $publickey,
        $signature,
        $raw_binary = false
    ) {
        if (!($publickey instanceof SignaturePublicKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 2: Expected an instance of SignaturePublicKey'
            );
        }
        $csum = self::checksumStream($input, $publickey, true);
        return AsymmetricCrypto::verify(
            $csum,
            $publickey,
            $signature,
            $raw_binary
        );
    }
    
    /**
     * Get the configuration
     * 
     * @param string $header
     * @param string $mode
     * @return \ParagonIE\Halite\Config
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfig($header, $mode = 'encrypt')
    {
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 65) {
            throw new CryptoException\InvalidMessage(
                'Invalid version tag'
            );
        }
        $major = \ord($header[2]);
        $minor = \ord($header[3]);
        if ($mode === 'encrypt') {
            return new Config(
                self::getConfigEncrypt($major, $minor)
            );
        } elseif ($mode === 'seal') {
            return new Config(
                self::getConfigSeal($major, $minor)
            );
        } elseif ($mode === 'checksum') {
            return new Config(
                self::getConfigChecksum($major, $minor)
            );
        }
    }
    
    /**
     * Get the configuration for encrypt operations
     * 
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigEncrypt($major, $minor)
    {
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }
    
    /**
     * Get the configuration for seal operations
     * 
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigSeal($major, $minor)
    {
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        } elseif ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'HKDF_SBOX' => 'Halite|EncryptionKey',
                        'HKDF_AUTH' => 'AuthenticationKeyFor_|Halite'
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }
    
    /**
     * Get the configuration for encrypt operations
     * 
     * @param int $major
     * @param int $minor
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfigChecksum($major, $minor)
    {
        if ($major === 1) {
            switch ($minor) {
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => false,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        } elseif ($major === 2) {
            switch ($minor) {
                case 0:
                    return [
                        'CHECKSUM_PUBKEY' => true,
                        'BUFFER' => 1048576,
                        'HASH_LEN' => \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }
    
    /**
     * Split a key using HKDF
     * 
     * @param \ParagonIE\Halite\Contract\KeyInterface $master
     * @param string $salt
     * @param Config $config
     * @return array
     */
    protected static function splitKeys(
        \ParagonIE\Halite\Contract\KeyInterface $master,
        $salt = null,
        Config $config = null
    ) {
        $binary = $master->get();
        return [
            Util::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                $config->HKDF_SBOX,
                $salt
            ),
            Util::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                $config->HKDF_AUTH,
                $salt
            )
        ];
    }
    
    /**
     * Stream encryption - Do not call directly
     * 
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param EncryptionKey $encKey
     * @param string $nonce
     * @param resource $mac (hash context)
     * @param Config $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamEncrypt(
        ReadOnlyFile $input,
        MutableFile $output,
        KeyInterface $encKey,
        $nonce,
        $mac,
        Config $config
    ) {
        if (!($encKey instanceof EncryptionKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionKey'
            );
        }
        $initHash = $input->getHash();
        // Begin the streaming decryption
        $size = $input->getSize();
        while ($input->remainingBytes() > 0) {
            $read = $input->readBytes(
                ($input->getPos() + $config->BUFFER) > $size
                    ? ($size - $input->getPos())
                    : $config->BUFFER
            );
            
            $encrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->get()
            );
            \hash_update($mac, $encrypted);
            $output->writeBytes($encrypted);
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);
        // Check that our input file was not modified before we MAC it
        if (!\hash_equals($input->gethash(), $initHash)) {
            throw new CryptoException\FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
        return $output->writeBytes(
            \hash_final($mac, true)
        );
    }
    
    /**
     * Stream decryption - Do not call directly
     * 
     * @param ReadOnlyFile $input
     * @param MutableFile $output
     * @param Key $encKey
     * @param string $nonce
     * @param resource $mac (hash context)
     * @param Config $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamDecrypt(
        ReadOnlyFile $input,
        MutableFile $output,
        KeyInterface $encKey,
        $nonce,
        $mac,
        Config $config,
        array &$chunk_macs
    ) {
        if (!($encKey instanceof EncryptionKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 3: Expected an instance of EncryptionKey'
            );
        }
        $start = $input->getPos();
        $cipher_end = $input->getSize() - $config->MAC_SIZE;
        // Begin the streaming decryption
        $input->reset($start);
        
        while ($input->remainingBytes() > $config->MAC_SIZE) {
            if (($input->getPos() + $config->BUFFER) > $cipher_end) {
                $read = $input->readBytes(
                    $cipher_end - $input->getPos()
                );
            } else {
                $read = $input->readBytes($config->BUFFER);
            }
            \hash_update($mac, $read);
            $calcMAC = \hash_copy($mac);
            if ($calcMAC === false) {
                throw new CryptoException\CannotPerformOperation(
                    'An unknown error has occurred'
                );
            }
            $calc = \hash_final($calcMAC, true);
            
            if (empty($chunk_macs)) {
                throw new CryptoException\InvalidMessage(
                    'Invalid message authentication code'
                );
            } else {
                $chkmac = \array_shift($chunk_macs);
                if (!\hash_equals($chkmac, $calc)) {
                    throw new CryptoException\InvalidMessage(
                        'Invalid message authentication code'
                    );
                }
            }
            
            $decrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->get()
            );
            $output->writeBytes($decrypted);
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);
        return true;
    }
    
    /**
     * Recalculate and verify the HMAC of the input file
     * 
     * @param resource $input
     * @param resource $mac (hash context)
     * @param Config $config
     * 
     * @return Hashes of various chunks
     * @throws FileAlert\AccessDenied
     */
    final private static function streamVerify(
        ReadOnlyFile $input,
        $mac,
        Config $config
    ) {
        $start = $input->getPos();
        
        $cipher_end = $input->getSize() - $config->MAC_SIZE;
        $input->reset($cipher_end);
        $stored_mac = $input->readBytes($config->MAC_SIZE);
        $input->reset($start);
        
        $chunk_macs = [];
        
        $break = false;
        while (!$break && $input->getPos() < $cipher_end) {
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($input->getPos() + $config->BUFFER >= $cipher_end) {
                $break = true;
                $read = $input->readBytes($cipher_end - $input->getPos());
            } else {
                $read = $input->readBytes($config->BUFFER);
            }
            
            /**
             * We're updating our HMAC and nothing else
             */
            \hash_update($mac, $read);
            
            /**
             * Store a MAC of each chunk
             */
            $chunkMAC = \hash_copy($mac);
            if ($chunkMAC === false) {
                throw new CryptoException\CannotPerformOperation(
                    'An unknown error has occurred'
                );
            }
            $chunk_macs []= \hash_final($chunkMAC, true);
        }
        
        /**
         * We should now have enough data to generate an identical HMAC
         */
        $finalHMAC = \hash_final($mac, true);
        
        /**
         * Use hash_equals() to be timing-invariant
         */
        if (!\hash_equals($finalHMAC, $stored_mac)) {
            throw new CryptoException\InvalidMessage(
                'Invalid message authentication code'
            );
        }
        $input->reset($start);
        return $chunk_macs;
    }
}
