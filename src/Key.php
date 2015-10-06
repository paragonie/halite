<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Asymmetric\SecretKey as ASecretKey;
use ParagonIE\Halite\Asymmetric\PublicKey as APublicKey;
use ParagonIE\Halite\Symmetric\SecretKey;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Contract;

/**
 * Symmetric Key Crypography uses one secret key, while Asymmetric Key Cryptography
 * uses a secret key and public key pair
 */
class Key implements Contract\CryptoKeyInterface
{
    // FLAGS:
    const SECRET_KEY       =   1;
    const PUBLIC_KEY       =   2;
    const ENCRYPTION       =   4;
    const SIGNATURE        =   8;
    const ASYMMETRIC       =  16;
    
    // SHORTCUTS:
    const CRYPTO_SECRETBOX =  5;
    const CRYPTO_AUTH      =  9;
    const CRYPTO_BOX       = 20;
    const CRYPTO_SIGN      = 24;
    
    private $is_public_key = false;
    private $is_signing_key = false;
    private $is_asymmetric_key = false;
    private $key_material = '';
    
    /**
     * Don't let this ever succeed
     * 
     * @throws CryptoException\CannotCloneKey
     */
    public function __clone()
    {
        throw new CryptoException\CannotCloneKey;
    }
    
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $public - Is this a public key?
     * @param bool $signing - Is this a signing key?
     * @param bool $asymmetric - Is this being used in asymmetric cryptography?
     */
    public function __construct(
        $keyMaterial = '',
        ...$args
    ) {
        $public = \count($args) >= 1 ? $args[0] : false;
        $signing = \count($args) >= 2 ? $args[1] : false;
        $asymmetric = \count($args) >= 3 ? $args[2] : false;
        
        $this->key_material = $keyMaterial;
        $this->is_public_key = $public;
        $this->is_signing_key = $signing;
        if ($public && !$asymmetric) {
            // This is implied.
            $asymmetric = true;
        }
        $this->is_asymmetric_key = $asymmetric;
    }
    
    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct()
    {
        if (!$this->is_public_key) {
            \Sodium\memzero($this->key_material);
            $this->key_material = null;
        }
    }
    
    /**
     * Don't serialize
     */
    public function __sleep()
    {
        throw new CryptoException\CannotSerializeKey;
    }
    
    /**
     * Get public keys
     * 
     * @return string
     */
    public function __toString()
    {
        if ($this->is_public_key) {
            return $this->key_material;
        }
    }
    
    /**
     * Derive an encryption key from a password and a salt
     * 
     * @param string $password
     * @param string $salt
     * @param int $type
     * @return array|\ParagonIE\Halite\Key
     * @throws CryptoException\InvalidFlags
     */
    public static function deriveFromPassword(
        $password,
        $salt,
        $type = self::CRYPTO_SECRETBOX
    ) {
        // Set this to true to flag a key as a signing key
        $signing = false;
        
        /**
         * Are we doing public key cryptography?
         */
        if (($type & self::ASYMMETRIC) !== 0) {
            /**
             * Are we doing encryption or digital signing?
             */
            if (($type & self::ENCRYPTION) !== 0) {
                $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                    \Sodium\CRYPTO_BOX_SECRETKEYBYTES,
                    $password,
                    $salt, 
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
                );
                $public_key = \Sodium\crypto_box_publickey_from_secretkey(
                    $secret_key
                );
            } elseif (($type & self::SIGNATURE) !== 0) {
                // Digital signature keypair
                $signing = true;
                $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                    \Sodium\CRYPTO_SIGN_SECRETKEYBYTES,
                    $password,
                    $salt,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
                );
                $public_key = \Sodium\crypto_sign_publickey_from_secretkey(
                    $secret_key
                );
            } else {
                throw new CryptoException\InvalidFlags(
                    'Must specify encryption or authentication'
                );
            }
            
            // Let's return an array with two keys
            return [
                new ASecretKey($secret_key, $signing), // Secret key
                new APublicKey($public_key, $signing)  // Public key
            ];
        } elseif ($type & self::SECRET_KEY !== 0) {
            /**
             * Are we doing encryption or authentication?
             */
            if ($type & self::SIGNATURE !== 0) {
                $signing = true;
            }
            $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
            return new SecretKey($secret_key, $signing);
        } else {
            throw new CryptoException\InvalidFlags(
                'Must specify symmetric-key or asymmetric-key'
            );
        }
    }
    
    /**
     * Load a key from a file
     * 
     * @param string $filePath
     * @param int $type
     * @return array|\ParagonIE\Halite\Key
     * @throws CryptoException\InvalidFlags
     */
    public static function fromFile(
        $filePath,
        $type = self::CRYPTO_SECRETBOX
    ) {
        // Set this to true to flag a key as a signing key
        $signing = false;
        
        /**
         * Are we doing public key cryptography?
         */
        if (($type & self::ASYMMETRIC) !== 0) {
            /**
             * Are we doing encryption or digital signing?
             */
            $secret_key = \file_get_contents($filePath);
            if (($type & self::ENCRYPTION) !== 0) {
                $public_key = \Sodium\crypto_box_publickey_from_secretkey(
                    $secret_key
                );
            } elseif (($type & self::SIGNATURE) !== 0) {
                // Digital signature keypair
                $signing = true;
                $public_key = \Sodium\crypto_sign_publickey_from_secretkey(
                    $secret_key
                );
            } else {
                throw new CryptoException\InvalidFlags(
                    'Must specify encryption or authentication'
                );
            }
            
            // Let's return an array with two keys
            return [
                new ASecretKey($secret_key, $signing), // Secret key
                new APublicKey($public_key, $signing)  // Public key
            ];
        } elseif ($type & self::SECRET_KEY !== 0) {
            /**
             * Are we doing encryption or authentication?
             */
            if ($type & self::SIGNATURE !== 0) {
                $signing = true;
            }
            $secret_key = \file_get_contents($filePath);
            return new SecretKey($secret_key, $signing);
        } else {
            throw new CryptoException\InvalidFlags(
                'Must specify symmetric-key or asymmetric-key'
            );
        }
    }
    
    /**
     * Generate a key
     * 
     * @param int $type
     * @param &string $secret_key - Reference to optional variable to store secret key in
     * @return array|Key
     */
    public static function generate(
        $type = self::CRYPTO_SECRETBOX,
        &$secret_key = null
    ) {
        // Set this to true to flag a key as a signing key
        $signing = false;
        
        /**
         * Are we doing public key cryptography?
         */
        if (($type & self::ASYMMETRIC) !== 0) {
            /**
             * Are we doing encryption or digital signing?
             */
            if (($type & self::ENCRYPTION) !== 0) {
                // Encryption keypair
                $kp = \Sodium\crypto_box_keypair();
                $secret_key = \Sodium\crypto_box_secretkey($kp);
                $public_key = \Sodium\crypto_box_publickey($kp);
            } elseif (($type & self::SIGNATURE) !== 0) {
                // Digital signature keypair
                $signing = true;
                $kp = \Sodium\crypto_sign_keypair();
                $secret_key = \Sodium\crypto_sign_secretkey($kp);
                $public_key = \Sodium\crypto_sign_publickey($kp);
            } else {
                throw new CryptoException\InvalidFlags(
                    'Must specify encryption or authentication'
                );
            }
            
            // Let's wipe our $kp variable
            \Sodium\memzero($kp);
            
            // Let's return an array with two keys
            return [
                new ASecretKey($secret_key, $signing), // Secret key
                new APublicKey($public_key, $signing)  // Public key
            ];
        } elseif ($type & self::SECRET_KEY !== 0) {
            /**
             * Are we doing encryption or authentication?
             */
            if ($type & self::ENCRYPTION !== 0) {
                $secret_key = \random_bytes(
                    \Sodium\CRYPTO_SECRETBOX_KEYBYTES
                );
            } elseif ($type & self::SIGNATURE !== 0) {
                $signing = true;
                
                // ...let it throw, let it throw!
                $secret_key = \random_bytes(
                    \Sodium\CRYPTO_AUTH_KEYBYTES
                );
            }
            return new SecretKey($secret_key, $signing);
        } else {
            throw new CryptoException\InvalidFlags(
                'Must specify symmetric-key or asymmetric-key'
            );
        }
    }
    
    /**
     * Get the actual key material
     * 
     * @return string
     * @throws CryptoException\CannotAccessKey
     */
    public function get()
    {
        return $this->key_material;
    }
    
    /**
     * Is this a part of a key pair?
     * 
     * @return bool
     */
    public function isAsymmetricKey()
    {
        return $this->is_asymmetric_key;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isEncryptionKey()
    {
        return !$this->is_signing_key;
    }
    
    /**
     * Is this a public key?
     * 
     * @return bool
     */
    public function isPublicKey()
    {
        return $this->is_public_key;
    }
    
    /**
     * Is this a secret key?
     * 
     * @return bool
     */
    public function isSecretKey()
    {
        return !$this->is_public_key;
    }
    
    /**
     * Is this a signing key?
     * 
     * @return bool
     */
    public function isSigningKey()
    {
        return $this->is_signing_key;
    }
    
    /**
     * Save a copy of the key to a file
     * 
     * @param string $filePath
     * @return bool|int
     */
    public static function saveToFile($filePath)
    {
        return \file_put_contents($filePath, $this->key_material);
    }
}
