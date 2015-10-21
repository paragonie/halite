<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Asymmetric\SecretKey as AsymmetricSecretKey;
use ParagonIE\Halite\Asymmetric\PublicKey as AsymmetricPublicKey;
use ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Contract;

/**
 * Symmetric Key Crypography uses one secret key, while Asymmetric Key Cryptography
 * uses a secret key and public key pair
 */
abstract class Key implements Contract\CryptoKeyInterface
{
    // FLAGS:
    const SECRET_KEY       =   1;
    const PUBLIC_KEY       =   2;
    const ENCRYPTION       =   4;
    const SIGNATURE        =   8;
    const ASYMMETRIC       =  16;
    
    // ALIAS:
    const AUTHENTICATION   =   8;
    
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
        echo "\t", 'CONSTRUCT', "\t", $this->getHash(), "\t", microtime(true), "\n";
        // Workaround: Inherited classes have simpler constructors:
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
     * Hide this from var_dump(), etc.
     * 
     * @return array
     */
    public function __debugInfo()
    {
        // We exclude $this->key_material
        return [
            'key' => \Sodium\bin2hex($this->key_material),
            'is_asymmetric_key' => $this->is_asymmetric_key,
            'is_public_key' => $this->is_public_key,
            'is_signing_key' => $this->is_signing_key
        ];
    }
    
    /**
     * Make sure you wipe the key from memory on destruction
     */
    public function __destruct()
    {
        echo "\t", 'DESTRUCT', "\t", $this->getHash(), "\t", microtime(true), "\n";
    }
    
    /**
     * Don't allow this object to ever be serialized
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
        return '';
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
        if (self::hasFlag($type, self::ASYMMETRIC)) {
            /**
             * Are we doing encryption or digital signing?
             */
            if (self::hasFlag($type, self::ENCRYPTION)) {
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
            } elseif (self::hasFlag($type, self::SIGNATURE)) {
                // Digital signature keypair
                $signing = true;
                $seed = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                    \Sodium\CRYPTO_SIGN_SEEDBYTES,
                    $password,
                    $salt,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
                );
                $keypair = \Sodium\crypto_sign_seed_keypair($seed);
                $secret_key = \Sodium\crypto_sign_secretkey($keypair);
                $public_key = \Sodium\crypto_sign_publickey($keypair);
                \Sodium\memzero($keypair);
                \Sodium\memzero($seed);
            } else {
                throw new CryptoException\InvalidFlags(
                    'Must specify encryption or authentication'
                );
            }
            
            // Let's return an array with two keys
            return [
                new AsymmetricSecretKey($secret_key, $signing), // Secret key
                new AsymmetricPublicKey($public_key, $signing)  // Public key
            ];
        /**
         * Symmetric-key implies secret-key:
         */
        } elseif (self::hasFlag($type, self::SECRET_KEY)) {
            /**
             * Are we doing encryption or authentication?
             */
            if (self::hasFlag($type, self::SIGNATURE)) {
                $signing = true;
                $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                    \Sodium\CRYPTO_AUTH_KEYBYTES,
                    $password,
                    $salt,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
                );
            } else {
                $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                    \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
                    $password,
                    $salt,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
                );
            }
            return new SymmetricKey($secret_key, $signing);
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
        if (self::hasFlag($type, self::ASYMMETRIC)) {
            /**
             * Are we doing encryption or digital signing?
             */
            $secret_key = \file_get_contents($filePath);
            if (self::hasFlag($type, self::ENCRYPTION)) {
                $public_key = \Sodium\crypto_box_publickey_from_secretkey(
                    $secret_key
                );
            } elseif (self::hasFlag($type, self::SIGNATURE)) {
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
                new AsymmetricSecretKey($secret_key, $signing), // Secret key
                new AsymmetricPublicKey($public_key, $signing)  // Public key
            ];
        } elseif (self::hasFlag($type, self::SECRET_KEY)) {
            /**
             * Are we doing encryption or authentication?
             */
            if (self::hasFlag($type, self::SIGNATURE)) {
                $signing = true;
            }
            $secret_key = \file_get_contents($filePath);
            return new SymmetricKey($secret_key, $signing);
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
        if (self::hasFlag($type, self::ASYMMETRIC)) {
            /**
             * Are we doing encryption or digital signing?
             */
            if (self::hasFlag($type, self::ENCRYPTION)) {
                // Encryption keypair
                $kp = \Sodium\crypto_box_keypair();
                $secret_key = \Sodium\crypto_box_secretkey($kp);
                $public_key = \Sodium\crypto_box_publickey($kp);
            } elseif (self::hasFlag($type, self::SIGNATURE)) {
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
            $secret = new AsymmetricSecretKey($secret_key, $signing);
            $public = new AsymmetricPublicKey($public_key, $signing);
            return [$secret, $public];
        } elseif (self::hasFlag($type, self::SECRET_KEY)) {
            /**
             * Are we doing encryption or authentication?
             */
            if (self::hasFlag($type, self::ENCRYPTION)) {
                $secret_key = \Sodium\randombytes_buf(
                    \Sodium\CRYPTO_SECRETBOX_KEYBYTES
                );
            } elseif (self::hasFlag($type, self::SIGNATURE)) {
                $signing = true;
                $secret_key = \Sodium\randombytes_buf(
                    \Sodium\CRYPTO_AUTH_KEYBYTES
                );
            }
            return new SymmetricKey($secret_key, $signing);
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
    public function saveToFile($filePath)
    {
        return \file_put_contents($filePath, $this->key_material);
    }
    
    /**
     * Does this integer contain this flag?
     * 
     * @param int $int
     * @param int $flag
     * @return bool
     */
    public static function hasFlag($int, $flag)
    {
        return ($int & $flag) !== 0;
    }
    
    public function getHash()
    {
        return "Hash: ".\Sodium\bin2hex(
            \Sodium\crypto_generichash(
                \spl_object_hash($this)
            )
        );
    }
}
