<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Halite;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util as CryptoUtil;

class File implements \ParagonIE\Halite\Contract\Crypto\FileInterface
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
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        self::encryptResource(
            $inputHandle,
            $outputHandle,
            $key
        );
        
        \fclose($inputHandle);
        \fclose($outputHandle);
    }
    
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
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        self::decryptResource(
            $inputHandle,
            $outputHandle,
            $key
        );
        
        \fclose($inputHandle);
        \fclose($outputHandle);
    }
    
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
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        self::sealResource(
            $inputHandle,
            $outputHandle,
            $publickey
        );
        
        \fclose($inputHandle);
        \fclose($outputHandle);
    }
    
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
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        self::unsealResource(
            $inputHandle,
            $outputHandle,
            $secretkey
        );
        
        \fclose($inputHandle);
        \fclose($outputHandle);
    }
    
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
        $config = self::getConfig(Halite::HALITE_VERSION, 'encrypt');
        
        // Generate a nonce and HKDF salt
        $firstnonce = \Sodium\randombytes_buf($config['NONCE_BYTES']);
        $hkdfsalt = \Sodium\randombytes_buf($config['HKDF_SALT_LEN']);
        
        // Let's split our key
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt);
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        // We no longer need $authKey after we set up the hash context
        unset($authKey);
        
        // Write the header
        $written = \fwrite($output, Halite::HALITE_VERSION, Halite::VERSION_TAG_LEN);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $written &= \fwrite($output, $firstnonce, \Sodium\CRYPTO_STREAM_NONCEBYTES);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $written &= \fwrite($output, $hkdfsalt, Halite::HKDF_SALT_LEN);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        \hash_update($mac, Halite::HALITE_VERSION);
        \hash_update($mac, $firstnonce);
        \hash_update($mac, $hkdfsalt);
        
        self::streamEncrypt($input, $output, new Key($encKey), $firstnonce, $mac, $config);
    }
    
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
        $firstnonce = self::readBytes($input, $config['NONCE_BYTES']);
        $hkdfsalt = self::readBytes($input, $config['HKDF_SALT_LEN']);
        
        // Split our keys, begin the HMAC instance
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt);
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        
        \hash_update($mac, $header);
        \hash_update($mac, $firstnonce);
        \hash_update($mac, $hkdfsalt);
        
        // This will throw an exception if it fails.
        $old_macs = self::streamVerify($input, \hash_copy($mac), $config);
        
        $ret = self::streamDecrypt(
            $input,
            $output, 
            new Key($encKey),
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
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
     */
    public static function sealResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $publickey
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
        $key = Asymmetric::getSharedSecret($eph_secret, $publickey, true);
        
        // Destroy the secre tkey after we have the shared secret
        unset($eph_secret);
        $config = self::getConfig(Halite::HALITE_VERSION, 'seal');
        
        // Generate a nonce as per crypto_box_seal
        $nonce = \Sodium\crypto_generichash(
            $eph_public->get().$publickey->get(),
            null,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        // Generate a random HKDF salt
        $hkdfsalt = \Sodium\randombytes_buf($config['HKDF_SALT_LEN']);
        
        // Split the keys
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt);
        
        // We no longer need the original key after we split it
        unset($key);
        
        $mac = \hash_init('sha256', HASH_HMAC, $authKey);
        // We no longer need to retain this after we've set up the hash context
        unset($authKey);
        
        $written = \fwrite($output, Halite::HALITE_VERSION, Halite::VERSION_TAG_LEN);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $written &= \fwrite($output, $eph_public->get(), \Sodium\CRYPTO_BOX_PUBLICKEYBYTES);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        $written &= \fwrite($output, $hkdfsalt, Halite::HKDF_SALT_LEN);
        if ($written === false) {
            throw new CryptoException\FileAccessDenied(
                'Could not write to the file'
            );
        }
        
        \hash_update($mac, Halite::HALITE_VERSION);
        \hash_update($mac, $eph_public->get());
        \hash_update($mac, $hkdfsalt);
        
        unset($eph_public);
        
        return self::streamEncrypt(
            $input,
            $output,
            new Key($encKey),
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
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
     */
    public static function unsealResource(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $secretkey
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
        $eph_public = self::readBytes($input, $config['PUBLICKEY_BYTES']);
        $hkdfsalt = self::readBytes($input, $config['HKDF_SALT_LEN']);
        
        $nonce = \Sodium\crypto_generichash(
            $eph_public . $public_key,
            null,
            \Sodium\CRYPTO_STREAM_NONCEBYTES
        );
        
        $ephemeral = new Key($eph_public, true, false, true);
        
        $key = Asymmetric::getSharedSecret(
            $secretkey, 
            $ephemeral,
            true
        );
        list ($encKey, $authKey) = self::splitKeys($key, $hkdfsalt);
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
            new Key($encKey),
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
     * Get the configuration
     * 
     * @param string $header
     * @param string $mode
     * @return array
     * @throws CryptoException\InvalidMessage
     */
    protected static function getConfig($header, $mode = 'encrypt')
    {
        if (\ord($header[0]) !== 49 || \ord($header[1]) !== 66) {
            throw new CryptoException\InvalidMessage(
                'Invalid version tag'
            );
        }
        $major = \ord($header[2]);
        $minor = \ord($header[3]);
        if ($mode === 'encrypt') {
            return self::getConfigEncrypt($major, $minor);
        } elseif ($mode === 'seal') {
            return self::getConfigSeal($major, $minor);
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
                    return [
                        'BUFFER' => 1048576,
                        'NONCE_BYTES' => \Sodium\CRYPTO_STREAM_NONCEBYTES,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32
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
                    return [
                        'BUFFER' => 1048576,
                        'HKDF_SALT_LEN' => 32,
                        'MAC_SIZE' => 32,
                        'PUBLICKEY_BYTES' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES
                    ];
            }
        }
        throw new CryptoException\InvalidMessage(
            'Invalid version tag'
        );
    }
    
    /**
     * Read from a stream; prevent partial reads
     * 
     * @param resource $stream
     * @param int $num
     * @throws FileAlert\AccessDenied
     */
    final private static function readBytes($stream, $num)
    {
        if ($num <= 0) {
            throw new \Exception('num < 0');
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
            $remaining = $num - CryptoUtil::safeStrlen($buf);
        } while ($remaining > 0);
        return $buf;
    }
    
    /**
     * Split a key using HKDF
     * 
     * @param \ParagonIE\Halite\Contract\CryptoKeyInterface $master
     * @param string $salt
     * @return array
     */
    protected static function splitKeys(\ParagonIE\Halite\Contract\CryptoKeyInterface $master, $salt = null)
    {
        $binary = $master->get();
        return [
            CryptoUtil::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                Halite::HKDF_SBOX,
                $salt
            ),
            CryptoUtil::hkdfBlake2b(
                $binary,
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                Halite::HKDF_AUTH,
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
     * @param array $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamEncrypt(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $encKey,
        $nonce,
        $mac,
        array $config
    ) {
        // Begin the streaming decryption
        while (!\feof($input)) {
            $read = \fread($input, $config['BUFFER']);
            if ($read === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not read from the file'
                );
            }
            $encrypted = \Sodium\crypto_stream_xor(
                $read,
                $nonce,
                $encKey->get()
            );
            
            \hash_update($mac, $encrypted);
            
            $written = \fwrite($output, $encrypted);
            if ($written === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not write to the file'
                );
            }
            \Sodium\increment($nonce);
        }
        \Sodium\memzero($nonce);
        
        \fwrite($output, \hash_final($mac, true));
    }
    
    /**
     * Stream decryption - Do not call directly
     * 
     * @param resource $input
     * @param resource $output
     * @param Key $encKey
     * @param string $nonce
     * @param resource $mac (hash context)
     * @param &array $config
     * @throws FileAlert\AccessDenied
     */
    final private static function streamDecrypt(
        $input,
        $output,
        \ParagonIE\Halite\Contract\CryptoKeyInterface $encKey,
        $nonce,
        $mac,
        array $config,
        array &$chunk_macs
    ) {
        // Reset the stream pointer to the beginning of the ciphertext
        $start = \ftell($input);
        if (\fseek($input, (-1 * $config['MAC_SIZE']), SEEK_END) === false) {
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
            if ($pos + $config['BUFFER'] >= $cipher_end) {
                $break = true;
                $read = self::readBytes($input, $cipher_end - $pos + 1);
            } else {
                $read = self::readBytes($input, $config['BUFFER']);
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
            $written = \fwrite($output, $decrypted);
            if ($written === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not write to the file'
                );
            }
            
            \Sodium\increment($nonce);
        }
    }
    
    /**
     * Recalculate and verify the HMAC of the input file
     * 
     * @param resource $input
     * @param Key $authKey
     * @param resource $mac (hash context)
     * @param &array $config
     * @return Hashes of various chunks
     * @throws FileAlert\AccessDenied
     */
    final private static function streamVerify(
        $input,
        $mac,
        array $config
    ) {
        $start = \ftell($input);
        if (\fseek($input, (-1 * $config['MAC_SIZE']), SEEK_END) === false) {
            throw new CryptoException\CannotPerformOperation(
                'Stream error'
            );
        }
        $cipher_end = \ftell($input) - 1;
        
        $stored_mac = self::readBytes($input, $config['MAC_SIZE']);
        
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
            if ($pos + $config['BUFFER'] >= $cipher_end) {
                $break = true;
                $read = self::readBytes($input, $cipher_end - $pos + 1);
            } else {
                $read = self::readBytes($input, $config['BUFFER']);
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