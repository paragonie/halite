<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidKey,
    InvalidSalt,
    InvalidType
};
use ParagonIE\Halite\{
    Asymmetric\EncryptionPublicKey,
    Asymmetric\EncryptionSecretKey,
    Asymmetric\SignaturePublicKey,
    Asymmetric\SignatureSecretKey,
    Symmetric\AuthenticationKey,
    Symmetric\EncryptionKey
};

/**
 * Class KeyFactory
 *
 * Class for generating specific key types
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class KeyFactory
{
    // For key derivation security levels:
    const INTERACTIVE = 'interactive';
    const MODERATE = 'moderate';
    const SENSITIVE = 'sensitive';

    /**
     * Generate an an authentication key (symmetric-key cryptography)
     *
     * @return AuthenticationKey
     * @throws CannotPerformOperation
     */
    public static function generateAuthenticationKey(): AuthenticationKey
    {
        try {
            $secretKey = \random_bytes(\SODIUM_CRYPTO_AUTH_KEYBYTES);
        } catch (\Throwable $ex) {
            throw new CannotPerformOperation($ex->getMessage());
        }
        return new AuthenticationKey(
            new HiddenString($secretKey)
        );
    }
    
    /**
     * Generate an an encryption key (symmetric-key cryptography)
     *
     * @return EncryptionKey
     * @throws CannotPerformOperation
     */
    public static function generateEncryptionKey(): EncryptionKey
    {
        try {
            $secretKey = \random_bytes(\SODIUM_CRYPTO_STREAM_KEYBYTES);
        } catch (\Throwable $ex) {
            throw new CannotPerformOperation($ex->getMessage());
        }
        return new EncryptionKey(
            new HiddenString($secretKey)
        );
    }
    
    /**
     * Generate a key pair for public key encryption
     *
     * @return \ParagonIE\Halite\EncryptionKeyPair
     */
    public static function generateEncryptionKeyPair(): EncryptionKeyPair
    {
        // Encryption keypair
        $kp = \sodium_crypto_box_keypair();
        $secretKey = \sodium_crypto_box_secretkey($kp);
        
        // Let's wipe our $kp variable
        \sodium_memzero($kp);
        return new EncryptionKeyPair(
            new EncryptionSecretKey(
                new HiddenString($secretKey)
            )
        );
    }
    
    /**
     * Generate a key pair for public key digital signatures
     *
     * @return SignatureKeyPair
     */
    public static function generateSignatureKeyPair(): SignatureKeyPair
    {
        // Encryption keypair
        $kp = \sodium_crypto_sign_keypair();
        $secretKey = \sodium_crypto_sign_secretkey($kp);
        
        // Let's wipe our $kp variable
        \sodium_memzero($kp);
        return new SignatureKeyPair(
            new SignatureSecretKey(
                new HiddenString($secretKey)
            )
        );
    }
    
    
    /**
     * Derive an authentication key (symmetric) from a password and salt
     *
     * @param HiddenString $password
     * @param string $salt
     * @param string $level Security level for KDF
     * 
     * @return AuthenticationKey
     * @throws CannotPerformOperation
     * @throws InvalidSalt
     * @throws InvalidType
     */
    public static function deriveAuthenticationKey(
        HiddenString $password,
        string $salt,
        string $level = self::INTERACTIVE
    ): AuthenticationKey {
        $kdfLimits = self::getSecurityLevels($level);
        // VERSION 2+ (argon2)
        if (Util::safeStrlen($salt) !== \SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new InvalidSalt(
                'Expected ' . \SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Util::safeStrlen($salt)
            );
        }
        $secretKey = \sodium_crypto_pwhash(
            \SODIUM_CRYPTO_AUTH_KEYBYTES,
            $password->getString(),
            $salt,
            $kdfLimits[0],
            $kdfLimits[1]
        );
        return new AuthenticationKey(
            new HiddenString($secretKey)
        );
    }
    
    /**
     * Derive an encryption key (symmetric-key cryptography) from a password
     * and salt
     *
     * @param HiddenString $password
     * @param string $salt
     * @param string $level Security level for KDF
     * 
     * @return EncryptionKey
     * @throws CannotPerformOperation
     * @throws InvalidSalt
     * @throws InvalidType
     */
    public static function deriveEncryptionKey(
        HiddenString $password,
        string $salt,
        string $level = self::INTERACTIVE
    ): EncryptionKey {
        $kdfLimits = self::getSecurityLevels($level);
        // VERSION 2+ (argon2)
        if (Util::safeStrlen($salt) !== \SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new InvalidSalt(
                'Expected ' . \SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Util::safeStrlen($salt)
            );
        }
        $secretKey = \sodium_crypto_pwhash(
            \SODIUM_CRYPTO_STREAM_KEYBYTES,
            $password->getString(),
            $salt,
            $kdfLimits[0],
            $kdfLimits[1]
        );
        return new EncryptionKey(
            new HiddenString($secretKey)
        );
    }
    
    /**
     * Derive a key pair for public key encryption from a password and salt
     * 
     * @param HiddenString $password
     * @param string $salt
     * @param string $level Security level for KDF
     * 
     * @return EncryptionKeyPair
     * @throws CannotPerformOperation
     * @throws InvalidSalt
     * @throws InvalidType
     */
    public static function deriveEncryptionKeyPair(
        HiddenString $password,
        string $salt,
        string $level = self::INTERACTIVE
    ): EncryptionKeyPair {
        $kdfLimits = self::getSecurityLevels($level);
        // VERSION 2+ (argon2)
        if (Util::safeStrlen($salt) !== \SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new InvalidSalt(
                'Expected ' . \SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Util::safeStrlen($salt)
            );
        }
        // Diffie Hellman key exchange key pair
        $seed = \sodium_crypto_pwhash(
            \SODIUM_CRYPTO_BOX_SEEDBYTES,
            $password->getString(),
            $salt,
            $kdfLimits[0],
            $kdfLimits[1]
        );
        $keyPair = \sodium_crypto_box_seed_keypair($seed);
        $secretKey = \sodium_crypto_box_secretkey($keyPair);
        
        // Let's wipe our $kp variable
        \sodium_memzero($keyPair);
        return new EncryptionKeyPair(
            new EncryptionSecretKey(
                new HiddenString($secretKey)
            )
        );
    }
    
    /**
     * Derive a key pair for public key signatures from a password and salt
     * 
     * @param HiddenString $password
     * @param string $salt
     * @param string $level Security level for KDF
     *
     * @return SignatureKeyPair
     * @throws InvalidSalt
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function deriveSignatureKeyPair(
        HiddenString $password,
        string $salt,
        string $level = self::INTERACTIVE
    ): SignatureKeyPair {
        $kdfLimits = self::getSecurityLevels($level);
        // VERSION 2+ (argon2)
        if (Util::safeStrlen($salt) !== \SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new InvalidSalt(
                'Expected ' . \SODIUM_CRYPTO_PWHASH_SALTBYTES . ' bytes, got ' . Util::safeStrlen($salt)
            );
        }
        // Digital signature keypair
        $seed = \sodium_crypto_pwhash(
            \SODIUM_CRYPTO_SIGN_SEEDBYTES,
            $password->getString(),
            $salt,
            $kdfLimits[0],
            $kdfLimits[1]
        );
        $keyPair = \sodium_crypto_sign_seed_keypair($seed);
        $secretKey = \sodium_crypto_sign_secretkey($keyPair);
        
        // Let's wipe our $kp variable
        \sodium_memzero($keyPair);
        return new SignatureKeyPair(
            new SignatureSecretKey(
                new HiddenString($secretKey)
            )
        );
    }

    /**
     * Returns a 2D array [OPSLIMIT, MEMLIMIT] for the appropriate security level.
     *
     * @param string $level
     * @return int[]
     * @throws InvalidType
     */
    public static function getSecurityLevels(string $level = self::INTERACTIVE): array
    {
        switch ($level) {
            case self::INTERACTIVE:
                return [
                    \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                    \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
                ];
            case self::MODERATE:
                return [
                    \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                    \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
                ];
            case self::SENSITIVE:
                return [
                    \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
                    \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE
                ];
            default:
                throw new InvalidType(
                    'Invalid security level for Argon2i'
                );
        }
    }

    /**
     * Load a symmetric authentication key from a string
     *
     * @param HiddenString $keyData
     * @return AuthenticationKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importAuthenticationKey(HiddenString $keyData): AuthenticationKey
    {
        return new AuthenticationKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load a symmetric encryption key from a string
     *
     * @param HiddenString $keyData
     * @return EncryptionKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importEncryptionKey(HiddenString $keyData): EncryptionKey
    {
        return new EncryptionKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load, specifically, an encryption public key from a string
     *
     * @param HiddenString $keyData
     * @return EncryptionPublicKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importEncryptionPublicKey(HiddenString $keyData): EncryptionPublicKey
    {
        return new EncryptionPublicKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load, specifically, an encryption secret key from a string
     *
     * @param HiddenString $keyData
     * @return EncryptionSecretKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importEncryptionSecretKey(HiddenString $keyData): EncryptionSecretKey
    {
        return new EncryptionSecretKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load, specifically, a signature public key from a string
     *
     * @param HiddenString $keyData
     * @return SignaturePublicKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importSignaturePublicKey(HiddenString $keyData): SignaturePublicKey
    {
        return new SignaturePublicKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load, specifically, a signature secret key from a string
     *
     * @param HiddenString $keyData
     * @return SignatureSecretKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importSignatureSecretKey(HiddenString $keyData): SignatureSecretKey
    {
        return new SignatureSecretKey(
            new HiddenString(
                self::getKeyDataFromString(
                    Hex::decode($keyData->getString())
                )
            )
        );
    }

    /**
     * Load an asymmetric encryption key pair from a string
     *
     * @param HiddenString $keyData
     * @return EncryptionKeyPair
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importEncryptionKeyPair(HiddenString $keyData): EncryptionKeyPair
    {
        return new EncryptionKeyPair(
            new EncryptionSecretKey(
                new HiddenString(
                    self::getKeyDataFromString(
                        Hex::decode($keyData->getString())
                    )
                )
            )
        );
    }

    /**
     * Load an asymmetric signature key pair from a string
     *
     * @param HiddenString $keyData
     * @return SignatureKeyPair
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function importSignatureKeyPair(HiddenString $keyData): SignatureKeyPair
    {
        return new SignatureKeyPair(
            new SignatureSecretKey(
                new HiddenString(
                    self::getKeyDataFromString(
                        Hex::decode($keyData->getString())
                    )
                )
            )
        );
    }
    
    /**
     * Load a symmetric authentication key from a file
     * 
     * @param string $filePath
     * @return AuthenticationKey
     *
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadAuthenticationKey(string $filePath): AuthenticationKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadEncryptionKey(string $filePath): EncryptionKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadEncryptionPublicKey(string $filePath): EncryptionPublicKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadEncryptionSecretKey(string $filePath): EncryptionSecretKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadSignaturePublicKey(string $filePath): SignaturePublicKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadSignatureSecretKey(string $filePath): SignatureSecretKey
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadEncryptionKeyPair(string $filePath): EncryptionKeyPair
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function loadSignatureKeyPair(string $filePath): SignatureKeyPair
    {
        if (!\is_readable($filePath)) {
            throw new CannotPerformOperation(
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
     * Export a cryptography key to a string (with a checksum)
     *
     * @param Key|KeyPair $key
     * @return HiddenString
     * @throws \TypeError
     */
    public static function export($key): HiddenString
    {
        if ($key instanceof KeyPair) {
            return self::export(
                $key->getSecretKey()
            );
        }
        if ($key instanceof Key) {
            return new HiddenString(
                Hex::encode(
                    Halite::HALITE_VERSION_KEYS . $key->getRawKeyMaterial() .
                    \sodium_crypto_generichash(
                        Halite::HALITE_VERSION_KEYS . $key->getRawKeyMaterial(),
                        '',
                        \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
                    )
                )
            );
        }
        throw new \TypeError('Expected a Key.');
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
            return self::saveKeyFile(
                $filename,
                $key->getSecretKey()->getRawKeyMaterial()
            );
        }
        return self::saveKeyFile($filename, $key->getRawKeyMaterial());
    }
    
    /**
     * Read a key from a file, verify its checksum
     * 
     * @param string $filePath
     * @return HiddenString
     * @throws CannotPerformOperation
     * @throws InvalidKey
     * @throws InvalidType
     */
    protected static function loadKeyFile(string $filePath): HiddenString
    {
        $fileData = \file_get_contents($filePath);
        if ($fileData === false) {
            throw new CannotPerformOperation(
                'Cannot load key from file: '. $filePath
            );
        }
        $data = Hex::decode($fileData);
        \sodium_memzero($fileData);
        return new HiddenString(
            self::getKeyDataFromString($data)
        );
    }
    
    /**
     * Take a stored key string, get the derived key (after verifying the
     * checksum)
     * 
     * @param string $data
     * @return string
     * @throws InvalidKey
     * @throws InvalidType
     */
    public static function getKeyDataFromString(string $data): string
    {
        $versionTag = Util::safeSubstr($data, 0, Halite::VERSION_TAG_LEN);
        $keyData = Util::safeSubstr(
            $data,
            Halite::VERSION_TAG_LEN,
            -\SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        );
        $checksum = Util::safeSubstr(
            $data,
            -\SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
            \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        );
        $calc = \sodium_crypto_generichash(
            $versionTag . $keyData,
            '',
            \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        );
        if (!\hash_equals($calc, $checksum)) {
            throw new InvalidKey(
                'Checksum validation fail'
            );
        }
        \sodium_memzero($data);
        \sodium_memzero($versionTag);
        \sodium_memzero($calc);
        \sodium_memzero($checksum);
        return $keyData;
    }
    
    /**
     * Save a key to a file
     * 
     * @param string $filePath
     * @param string $keyData
     * @return bool
     */
    protected static function saveKeyFile(
        string $filePath,
        string $keyData
    ): bool {
        $saved = \file_put_contents(
            $filePath,
            Hex::encode(
                Halite::HALITE_VERSION_KEYS . $keyData .
                \sodium_crypto_generichash(
                    Halite::HALITE_VERSION_KEYS . $keyData,
                    '',
                    \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
                )
            )
        );
        return $saved !== false;
    }
}
