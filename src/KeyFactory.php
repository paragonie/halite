<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\{
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey,
    Halite,
    Key,
    KeyPair,
    Util as CryptoUtil
};

/**
 * Class for generating specific key types
 */
abstract class KeyFactory
{
    /**
     * Generate an an authentication key (symmetric-key cryptography)
     * 
     * @param &string $secret_key
     * @return AuthenticationKey
     */
    public static function generateAuthenticationKey(string &$secret_key = ''): AuthenticationKey
    {
        $secret_key = \Sodium\randombytes_buf(
            \Sodium\CRYPTO_AUTH_KEYBYTES
        );
        return new AuthenticationKey($secret_key);
    }
    
    /**
     * Generate an an encryption key (symmetric-key cryptography)
     * 
     * @param &string $secret_key
     * @return EncryptionKey
     */
    public static function generateEncryptionKey(string &$secret_key = ''): EncryptionKey
    {
        $secret_key = \Sodium\randombytes_buf(
            \Sodium\CRYPTO_STREAM_KEYBYTES
        );
        return new EncryptionKey($secret_key);
    }
    
    /**
     * Generate a key pair for public key encryption
     * 
     * @param type $secret_key
     * @return \ParagonIE\Halite\EncryptionKeyPair
     */
    public static function generateEncryptionKeyPair(string &$secret_key = ''): EncryptionKeyPair
    {
        // Encryption keypair
        $kp = \Sodium\crypto_box_keypair();
        $secret_key = \Sodium\crypto_box_secretkey($kp);
        
        // Let's wipe our $kp variable
        \Sodium\memzero($kp);
        return new EncryptionKeyPair(
            new EncryptionSecretKey($secret_key)
        );
    }
    
    /**
     * Generate a key pair for public key digital signatures
     * 
     * @param string $secret_key
     * @return SignatureKeyPair
     */
    public static function generateSignatureKeyPair(string &$secret_key = ''): SignatureKeyPair
    {
        // Encryption keypair
        $kp = \Sodium\crypto_sign_keypair();
        $secret_key = \Sodium\crypto_sign_secretkey($kp);
        
        // Let's wipe our $kp variable
        \Sodium\memzero($kp);
        return new SignatureKeyPair(
            new SignatureSecretKey($secret_key)
        );
    }
    
    
    /**
     * Derive an authentication key (symmetric) from a password and salt
     * 
     * @param string $password
     * @param string $salt
     * @param bool $legacy Use scrypt?
     * 
     * @return AuthenticationKey
     * @throws CryptoException\InvalidSalt
     */
    public static function deriveAuthenticationKey(
        string $password,
        string $salt,
        bool $legacy = false
    ): AuthenticationKey {
        if ($legacy) {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
        } else {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            $secret_key = \Sodium\crypto_pwhash(
                \Sodium\CRYPTO_AUTH_KEYBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        return new AuthenticationKey($secret_key);
    }
    
    /**
     * Derive an encryption key (symmetric-key cryptography) from a password
     * and salt
     * 
     * @param string $password
     * @param string $salt
     * @param bool $legacy Use scrypt?
     * 
     * @return EncryptionKey
     * @throws CryptoException\InvalidSalt
     */
    public static function deriveEncryptionKey(
        string $password,
        string $salt,
        bool $legacy = false
    ): EncryptionKey {
        if ($legacy) {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                \Sodium\CRYPTO_STREAM_KEYBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
        } else {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            $secret_key = \Sodium\crypto_pwhash(
                \Sodium\CRYPTO_STREAM_KEYBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        return new EncryptionKey($secret_key);
    }
    
    /**
     * Derive a key pair for public key encryption from a password and salt
     * 
     * @param string $password
     * @param string $salt
     * @param bool $legacy Use scrypt?
     * 
     * @return EncryptionKeyPair
     * @throws CryptoException\InvalidSalt
     */
    public static function deriveEncryptionKeyPair(
        string $password,
        string $salt,
        bool $legacy = false
    ): EncryptionKeyPair {
        if ($legacy) {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            // Diffie Hellman key exchange key pair
            $seed = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                \Sodium\CRYPTO_BOX_SEEDBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
        } else {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            // Diffie Hellman key exchange key pair
            $seed = \Sodium\crypto_pwhash(
                \Sodium\CRYPTO_BOX_SEEDBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        $keypair = \Sodium\crypto_box_seed_keypair($seed);
        $secret_key = \Sodium\crypto_box_secretkey($keypair);
        
        // Let's wipe our $kp variable
        \Sodium\memzero($keypair);
        return new EncryptionKeyPair(
            new EncryptionSecretKey($secret_key)
        );
    }
    
    /**
     * Derive a key pair for public key signatures from a password and salt
     * 
     * @param string $password
     * @param string $salt
     * @param bool $legacy Use scrypt?
     *
     * @return SignatureKeyPair
     * @throws CryptoException\InvalidSalt
     */
    public static function deriveSignatureKeyPair(
        string $password,
        string $salt,
        bool $legacy = false
    ): SignatureKeyPair {
        if ($legacy) {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            // Digital signature keypair
            $seed = \Sodium\crypto_pwhash_scryptsalsa208sha256(
                \Sodium\CRYPTO_SIGN_SEEDBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
        } else {
            if (CryptoUtil::safeStrlen($salt) !== \Sodium\CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException\InvalidSalt(
                    'Expected ' . \Sodium\CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . CryptoUtil::safeStrlen($salt)
                );
            }
            // Digital signature keypair
            $seed = \Sodium\crypto_pwhash(
                \Sodium\CRYPTO_SIGN_SEEDBYTES,
                $password,
                $salt,
                \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            );
        }
        $keypair = \Sodium\crypto_sign_seed_keypair($seed);
        $secret_key = \Sodium\crypto_sign_secretkey($keypair);
        
        // Let's wipe our $kp variable
        \Sodium\memzero($keypair);
        return new SignatureKeyPair(
            new SignatureSecretKey($secret_key)
        );
    }
    
    /**
     * Load a symmetric authentication key from a file
     * 
     * @param string $filePath
     * @return EncryptionKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadAuthenticationKey(string $filePath): AuthenticationKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new AuthenticationKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load a symmetric encryption key from a file
     * 
     * @param string $filePath
     * @return EncryptionKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadEncryptionKey(string $filePath): EncryptionKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new EncryptionKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load, specifically, an encryption public key from a file
     * 
     * @param string $filePath
     * @return EncryptionPublicKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadEncryptionPublicKey(string $filePath): EncryptionPublicKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new EncryptionPublicKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load, specifically, an encryption public key from a file
     * 
     * @param string $filePath
     * @return EncryptionSecretKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadEncryptionSecretKey(string $filePath): EncryptionSecretKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new EncryptionSecretKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load, specifically, a signature public key from a file
     * 
     * @param string $filePath
     * @return SignaturePublicKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadSignaturePublicKey(string $filePath): SignaturePublicKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new SignaturePublicKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load, specifically, a signature secret key from a file
     * 
     * @param string $filePath
     * @return SignatureSecretKey
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadSignatureSecretKey(string $filePath): SignatureSecretKey
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new SignatureSecretKey(
            self::loadKeyFile($filePath)
        );
    }
    
    /**
     * Load an asymmetric encryption key pair from a file
     * 
     * @param string $filePath
     * @return EncryptionKeyPair
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadEncryptionKeyPair(string $filePath): EncryptionKeyPair
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new EncryptionKeyPair(
            new EncryptionSecretKey(
                self::loadKeyFile($filePath)
            )
        );
    }
    
    /**
     * Load an asymmetric signature key pair from a file
     * 
     * @param string $filePath
     * @return SignatureKeyPair
     *
     * @throws Alerts\CannotPerformOperation
     */
    public static function loadSignatureKeyPair(string $filePath): SignatureKeyPair
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: '. $filePath
            );
        }
        return new SignatureKeyPair(
            new SignatureSecretKey(
                self::loadKeyFile($filePath)
            )
        );
    }
    
    /**
     * Save a key to a file
     * 
     * @param Key|KeyPair $key
     * @param string $filename
     * @return bool
     */
    public static function save($key, string $filename = ''): bool
    {
        if ($key instanceof KeyPair) {
            return self::saveKeyFile($filename, $key->getSecretKey()->get());
        }
        return self::saveKeyFile($filename, $key->get());
    }
    
    /**
     * Read a key from a file, verify its checksum
     * 
     * @param string $filePath
     * @return string
     * @throws Alerts\CannotPerformOperation
     */
    protected static function loadKeyFile(string $filePath): string
    {
        $filedata = \file_get_contents($filePath);
        if ($filedata === false) {
            throw new Alerts\CannotPerformOperation(
                'Cannot load key from file: '. $filePath
            );
        }
        $data = \Sodium\hex2bin($filedata);
        \Sodium\memzero($filedata);
        return self::getKeyDataFromString($data);
    }
    
    /**
     * Take a stored key string, get the derived key (after verifying the
     * checksum)
     * 
     * @param string $data
     * @return string
     * @throws Alerts\InvalidKey
     */
    public static function getKeyDataFromString(string $data): string
    {
        $vtag = Util::safeSubstr($data, 0, Halite::VERSION_TAG_LEN);
        $kdat = Util::safeSubstr(
            $data,
            Halite::VERSION_TAG_LEN,
            -\Sodium\CRYPTO_GENERICHASH_BYTES_MAX
        );
        $csum = Util::safeSubstr(
            $data,
            -\Sodium\CRYPTO_GENERICHASH_BYTES_MAX,
            \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
        );
        $calc = \Sodium\crypto_generichash(
            $vtag . $kdat, 
            '',
            \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
        );
        if (!\hash_equals($calc, $csum)) {
            throw new Alerts\InvalidKey(
                'Checksum validation fail'
            );
        }
        \Sodium\memzero($data);
        \Sodium\memzero($vtag);
        \Sodium\memzero($calc);
        \Sodium\memzero($csum);
        return $kdat;
    }
    
    /**
     * Save a key to a file
     * 
     * @param string $filePath
     * @param string $keyData
     * @return int|bool
     */
    protected static function saveKeyFile(
        string $filePath,
        string $keyData
    ): bool {
        return (
            false !== \file_put_contents(
                $filePath,
                \Sodium\bin2hex(
                    Halite::HALITE_VERSION_KEYS . $keyData .
                    \Sodium\crypto_generichash(
                        Halite::HALITE_VERSION_KEYS . $keyData,
                        '',
                        \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                    )
                )
            )
        );
    }
}
