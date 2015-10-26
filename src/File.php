<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;
use \ParagonIE\Halite\Asymmetric\SecretKey as SecretKey;
use \ParagonIE\Halite\Asymmetric\PublicKey as PublicKey;
use \ParagonIE\Halite\Config;
use \ParagonIE\Halite\Halite;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;
use \ParagonIE\Halite\Util as CryptoUtil;

class File implements \ParagonIE\Halite\Contract\FileInterface
{
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
        SymmetricKey $key = null,
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
        SymmetricKey $key = null,
        $raw = false
    ) {
        // Input validation
        if (!\is_resource($fileHandle)) {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Expected input handle to be a resource'
            );
        }
        $config = self::getConfig(Halite::HALITE_VERSION_FILE, 'checksum');
        if ($key) {
            $state = \Sodium\crypto_generichash_init($key->get(), $config->HASH_LEN);
        } else {
            $state = \Sodium\crypto_generichash_init(null, $config->HASH_LEN);
        }
        $stat = \fstat($fileHandle);
        $size = $stat['size'];
        
        while (!\feof($fileHandle) && $size > 0) {
            if ($size < $config->BUFFER) {
                $read = self::readBytes($fileHandle, $size);
            } else {
                $read = self::readBytes($fileHandle, $config->BUFFER);
            }
            \Sodium\crypto_generichash_update($state, $read);
            $size -= CryptoUtil::safeStrlen($read);
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
     * @param SymmetricKey $key
     */
    public static function encryptFile(
        $inputFile,
        $outputFile,
        SymmetricKey $key
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
     * @param SymmetricKey $key
     */
    public static function decryptFile(
        $inputFile,
        $outputFile,
        SymmetricKey $key
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
     * @param PublicKey $publickey
     */
    public static function sealFile(
        $inputFile,
        $outputFile,
        PublicKey $publickey
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
     * @param SecretKey $secretkey
     */
    public static function unsealFile(
        $inputFile,
        $outputFile,
        SecretKey $secretkey
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
     * @param SecretKey $secretkey
     * @param bool $raw_binary
     * 
     * @return string
     */
    public static function signFile(
        $filename,
        SecretKey $secretkey,
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
     * @param PublicKey $publickey
     * @param string $signature
     */
    public static function verifyFile(
        $filename,
        PublicKey $publickey,
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
     * @param SymmetricKey $key
     */
    public static function encryptResource(
        $input,
        $output,
        SymmetricKey $key
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
        if (!$key->isSecretKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a secret key'
            );
        }
        if ($key->isAsymmetricKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a key intended for symmetric-key cryptography'
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
        self::writeBytes($output, Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        self::writeBytes($output, $firstnonce, \Sodium\CRYPTO_STREAM_NONCEBYTES);
        self::writeBytes($output, $hkdfsalt, $config->HKDF_SALT_LEN);
        
        \hash_update($mac, Halite::HALITE_VERSION_FILE);
        \hash_update($mac, $firstnonce);
        \hash_update($mac, $hkdfsalt);
        
        return self::streamEncrypt(
            $input,
            $output,
            new SymmetricKey($encKey),
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
     * @param SymmetricKey $key
     */
    public static function decryptResource(
        $input,
        $output,
        SymmetricKey $key
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
        if (!$key->isSecretKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a secret key'
            );
        }
        if ($key->isAsymmetricKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a key intended for symmetric-key cryptography'    
            );
        }
        
        // Parse the header, ensuring we get 4 bytes
        $header = self::readBytes($input, Halite::VERSION_TAG_LEN);
        
        // Load the config
        $config = self::getConfig($header, 'encrypt');
        
        // Let's grab the first nonce and salt
        $firstnonce = self::readBytes($input, $config->NONCE_BYTES);
        $hkdfsalt = self::readBytes($input, $config->HKDF_SALT_LEN);
        
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
            new SymmetricKey($encKey),
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
     * @param PublicKey $publickey
     */
    public static function sealResource(
        $input,
        $output,
        PublicKey $publickey
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
        if (!$publickey->isPublicKey()) {
            throw new CryptoException\InvalidKey(
                'Especter a public key'
            );
        }
        if (!$publickey->isAsymmetricKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a key intended for asymmetric-key cryptography'
            );
        }
        // Generate a new keypair for this encryption
        list ($eph_secret, $eph_public) = Key::generate(Key::CRYPTO_BOX);
        
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
        
        self::writeBytes($output, Halite::HALITE_VERSION_FILE, Halite::VERSION_TAG_LEN);
        self::writeBytes($output, $eph_public->get(), \Sodium\CRYPTO_BOX_PUBLICKEYBYTES);
        self::writeBytes($output, $hkdfsalt, $config->HKDF_SALT_LEN);
        
        \hash_update($mac, Halite::HALITE_VERSION_FILE);
        \hash_update($mac, $eph_public->get());
        \hash_update($mac, $hkdfsalt);
        
        unset($eph_public);
        
        return self::streamEncrypt(
            $input,
            $output,
            new SymmetricKey($encKey),
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
     * @param SecretKey $secretkey
     */
    public static function unsealResource(
        $input,
        $output,
        SecretKey $secretkey
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
        if (!$secretkey->isSecretKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a secret key'
            );
        }
        if (!$secretkey->isAsymmetricKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a key intended for asymmetric-key cryptography'
            );
        }
        
        $secret_key = $secretkey->get();
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        
        // Parse the header, ensuring we get 4 bytes
        $header = self::readBytes($input, Halite::VERSION_TAG_LEN);
        // Load the config
        $config = self::getConfig($header, 'seal');
        // Let's grab the public key and salt
        $eph_public = self::readBytes($input, $config->PUBLICKEY_BYTES);
        $hkdfsalt = self::readBytes($input, $config->HKDF_SALT_LEN);
        
        $nonce = \Sodium\crypto_generichash(
            $eph_public . $public_key,
            null,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        $ephemeral = new PublicKey($eph_public);
        
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
            new SymmetricKey($encKey),
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
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
     * @param bool $raw_binary Don't hex encode?
     */
    public static function signResource(
        $input,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey,
        $raw_binary = false
    ) {
        $csum = self::checksumResource($input, null, true);
        return AsymmetricCrypto::sign($csum, $secretkey, $raw_binary);
    }
    
    /**
     * Verify the contents of a file
     * 
     * @param $input (file handle)
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
     * @param string $signature
     * @param bool $raw_binary Don't hex encode?
     * 
     * @return bool
     */
    public static function verifyResource(
        $input,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey,
        $signature,
        $raw_binary = false
    ) {
        $csum = self::checksumResource($input, null, true);
        return AsymmetricCrypto::verify($csum, $publickey, $signature, $raw_binary);
    }
    
    /**
     * Read from a stream; prevent partial reads
     * 
     * @param resource $stream
     * @param int $num
     * @return string
     * @throws FileAlert\AccessDenied
     */
    final public static function readBytes($stream, $num)
    {
        if ($num <= 0) {
            throw new \Exception('num < 0');
        }
        $fstat = \fstat($stream);
        $pos = \ftell($stream);
        if (($pos + $num) > $fstat['size']) {
            \var_dump(['pos' => $pos, 'num' => $num, 'size' => $fstat['size']]);
            exit;
            throw new \Exception('Out-of-bounds read');
        }
        $buf = '';
        $remaining = $num;
        do {
            if ($remaining <= 0) {
                break;
            }
            $read = \fread($stream, $remaining);
            if ($read === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not read from the file'
                );
            }
            $buf .= $read;
            $remaining -= CryptoUtil::safeStrlen($read);
        } while ($remaining > 0);
        return $buf;
    }

    /**
     * Write to a stream; prevent partial writes
     * 
     * @param resource $stream
     * @param string $buf
     * @param int $num (number of bytes)
     * @throws FileAlert\AccessDenied
     */
    final public static function writeBytes($stream, $buf, $num = null)
    {
        $bufSize = CryptoUtil::safeStrlen($buf);
        if ($num === null || $num > $bufSize) {
            $num = $bufSize;
        }
        if ($num < 0) {
            throw new \Exception('num < 0');
        }
        $remaining = $num;
        do {
            if ($remaining <= 0) {
                break;
            }
            $written = \fwrite($stream, $buf, $remaining);
            if ($written === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not write to the file'
                );
            }
            $buf = CryptoUtil::safeSubstr($buf, $written, null);
            $remaining -= $written;
        } while ($remaining > 0);
        return $num;
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
        if ($header === "\x31\x42\x00\x01") {
            // Original version, remove before 1.0.0
        } elseif (\ord($header[0]) !== 49 || \ord($header[1]) !== 65) {
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
        if ($major === 0) {
            switch ($minor) {
                case 1:
                case 6:
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
        if ($major === 0) {
            switch ($minor) {
                case 1:
                case 6:
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
        if ($major === 0) {
            switch ($minor) {
                case 1:
                case 6:
                    return [
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
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $master
     * @param string $salt
     * @param Config $config
     * @return array
     */
    protected static function splitKeys(
        \ParagonIE\Halite\Contract\CryptoKeyInterface $master,
        $salt = null,
        Config $config = null
    ) {
        $binary = $master->get();
        return [
            CryptoUtil::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                $config->HKDF_SBOX,
                $salt
            ),
            CryptoUtil::hkdfBlake2b(
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
     * @param resource $input
     * @param resource $output
     * @param Key $encKey
     * @param string $nonce
     * @param resource $mac (hash context)
     * @param Config $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamEncrypt(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $encKey,
        $nonce,
        $mac,
        Config $config
    ) {
        $fstat = \fstat($input);
        $fsize = $fstat['size'];
        $break = false;
        // Begin the streaming decryption
        while (!\feof($input) && !$break) {
            $pos = \ftell($input);
            if (($pos + $config->BUFFER) > $fsize) {
                $break = true;
                $read = self::readBytes($input, ($fsize - $pos));
            } else {
                $read = self::readBytes($input, $config->BUFFER);
            }
            $encrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->get()
            );
            
            \hash_update($mac, $encrypted);
            
            self::writeBytes($output, $encrypted);
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);        
        return self::writeBytes($output, \hash_final($mac, true));
    }
    
    /**
     * Stream decryption - Do not call directly
     * 
     * @param resource $input
     * @param resource $output
     * @param Key $encKey
     * @param string $nonce
     * @param resource $mac (hash context)
     * @param Config $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamDecrypt(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $encKey,
        $nonce,
        $mac,
        Config $config,
        array &$chunk_macs
    ) {
        // Reset the stream pointer to the beginning of the ciphertext
        $start = \ftell($input);
        if (\fseek($input, (-1 * $config->MAC_SIZE), SEEK_END) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        $cipher_end = \ftell($input) - 1;
        if (\fseek($input, $start, SEEK_SET) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        $break = false;
        while (!$break) {
            $pos = \ftell($input);
            if ($pos === false) {
                throw new CryptoException\CannotPerformOperation(
                    'Stream error'
                );
            }
            
            // Read the data from the input buffer
            if ($pos + $config->BUFFER >= $cipher_end) {
                $break = true;
                $read = self::readBytes($input, $cipher_end - $pos + 1);
            } else {
                $read = self::readBytes($input, $config->BUFFER);
            }
            
            // Let's reculcualte the MAC of this chunk, then verify it
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
            } elseif (!\hash_equals(\array_shift($chunk_macs), $calc)) {
                throw new CryptoException\InvalidMessage(
                    'Invalid message authentication code'
                );
            }
            
            $decrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->get()
            );
            self::writeBytes($output, $decrypted);
            \Sodium\increment($nonce);
        }
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
        $input,
        $mac,
        Config $config
    ) {
        $start = \ftell($input);
        if (\fseek($input, (-1 * $config->MAC_SIZE), SEEK_END) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        $cipher_end = \ftell($input) - 1;
        
        $stored_mac = self::readBytes($input, $config->MAC_SIZE);
        
        if (\fseek($input, $start, SEEK_SET) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        $chunk_macs = [];
        
        $break = false;
        while (!$break) {
            /**
             * First, grab the current position
             */
            $pos = \ftell($input);
            if ($pos === false) {
                throw new CryptoException\CannotPerformOperation(
                    'Stream error'
                );
            }
            if ($pos >= $cipher_end) {
                break;
            }
            /**
             * Would a full BUFFER read put it past the end of the
             * ciphertext? If so, only return a portion of the file.
             */
            if ($pos + $config->BUFFER >= $cipher_end) {
                $break = true;
                $read = self::readBytes($input, $cipher_end - $pos + 1);
            } else {
                $read = self::readBytes($input, $config->BUFFER);
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
        if (\fseek($input, $start, SEEK_SET) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        return $chunk_macs;
    }
}
