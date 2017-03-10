<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;
use \ParagonIE\Halite\Halite;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;

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
    public static function generateAuthenticationKey(&$secret_key = null)
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
    public static function generateEncryptionKey(&$secret_key = null)
    {
        $secret_key = \Sodium\randombytes_buf(
            \Sodium\CRYPTO_SECRETBOX_KEYBYTES
        );
        return new EncryptionKey($secret_key);
    }

    /**
     * Generate a key pair for public key encryption
     *
     * @param type $secret_key
     * @return \ParagonIE\Halite\EncryptionKeyPair
     */
    public static function generateEncryptionKeyPair(&$secret_key = null)
    {
        // Encryption keypair
        $kp         = \Sodium\crypto_box_keypair();
        $secret_key = \Sodium\crypto_box_secretkey($kp);

        // Let's wipe our $kp variable
        \Sodium\memzero($kp);
        return new EncryptionKeyPair(
            [new EncryptionSecretKey($secret_key)]
        );
    }

    /**
     * Generate a key pair for public key digital signatures
     *
     * @param type $secret_key
     * @return \ParagonIE\Halite\SignatureKeyPair
     */
    public static function generateSignatureKeyPair(&$secret_key = null)
    {
        // Encryption keypair
        $kp         = \Sodium\crypto_sign_keypair();
        $secret_key = \Sodium\crypto_sign_secretkey($kp);

        // Let's wipe our $kp variable
        \Sodium\memzero($kp);
        return new SignatureKeyPair(
            [new SignatureSecretKey($secret_key)]
        );
    }

    /**
     * Derive an authentication key (symmetric) from a password and salt
     *
     * @param string $password
     * @param string $salt
     * @return AuthenticationKey
     */
    public static function deriveAuthenticationKey(
        $password,
        $salt
    ) {
        $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
            \Sodium\CRYPTO_AUTH_KEYBYTES,
            $password,
            $salt,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        return new AuthenticationKey($secret_key);
    }

    /**
     * Derive an encryption key (symmetric-key cryptography) from a password
     * and salt
     *
     * @param &string $secret_key
     * @return EncryptionKey
     */
    public static function deriveEncryptionKey(
        $password,
        $salt
    ) {
        $secret_key = \Sodium\crypto_pwhash_scryptsalsa208sha256(
            \Sodium\CRYPTO_SECRETBOX_KEYBYTES,
            $password,
            $salt,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        return new EncryptionKey($secret_key);
    }

    /**
     * Derive a key pair for public key encryption from a password and salt
     *
     * @param string $secret_key
     * @return EncryptionKeyPair
     */
    public static function deriveEncryptionKeyPair(
        $password,
        $salt
    ) {
        // Digital signature keypair
        $seed       = \Sodium\crypto_pwhash_scryptsalsa208sha256(
            \Sodium\CRYPTO_SIGN_SEEDBYTES,
            $password,
            $salt,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        $keypair    = \Sodium\crypto_box_seed_keypair($seed);
        $secret_key = \Sodium\crypto_box_secretkey($keypair);

        // Let's wipe our $kp variable
        \Sodium\memzero($keypair);
        return new EncryptionKeyPair(
            [new EncryptionSecretKey($secret_key)]
        );
    }

    /**
     * Derive a key pair for public key signatures from a password and salt
     *
     * @param type $secret_key
     * @return \ParagonIE\Halite\SignatureKeyPair
     */
    public static function deriveSignatureKeyPair(
        $password,
        $salt
    ) {
        // Digital signature keypair
        $seed       = \Sodium\crypto_pwhash_scryptsalsa208sha256(
            \Sodium\CRYPTO_SIGN_SEEDBYTES,
            $password,
            $salt,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        $keypair    = \Sodium\crypto_sign_seed_keypair($seed);
        $secret_key = \Sodium\crypto_sign_secretkey($keypair);

        // Let's wipe our $kp variable
        \Sodium\memzero($keypair);
        return new SignatureKeyPair(
            [new SignatureSecretKey($secret_key)]
        );
    }

    /**
     * Load a symmetric authentication key from a file
     *
     * @param string $filePath
     * @return AuthenticationKey
     */
    public static function loadAuthenticationKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadEncryptionKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadEncryptionPublicKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadEncryptionSecretKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadSignaturePublicKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadSignatureSecretKey($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
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
     */
    public static function loadEncryptionKeyPair($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
            );
        }
        return new EncryptionKeyPair(
            [
                new EncryptionSecretKey(
                    self::loadKeyFile($filePath)
                ),
            ]);
    }

    /**
     * Load an asymmetric signature key pair from a file
     *
     * @param string $filePath
     * @return SignatureKeyPair
     */
    public static function loadSignatureKeyPair($filePath)
    {
        if (!\is_readable($filePath)) {
            throw new Alerts\CannotPerformOperation(
                'Cannot read keyfile: ' . $filePath
            );
        }
        return new SignatureKeyPair(
            [
                new SignatureSecretKey(
                    self::loadKeyFile($filePath)
                ),
            ]);
    }

    /**
     * Save a key to a file
     *
     * @param Key|KeyPair $key
     * @param string      $filename
     * @return int|boolean
     */
    public static function save($key, $filename = '')
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
    protected static function loadKeyFile($filePath)
    {
        $filedata = \file_get_contents($filePath);
        if ($filedata === false) {
            throw new Alerts\CannotPerformOperation(
                'Cannot load key from file: ' . $filePath
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
    public static function getKeyDataFromString($data)
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
            null,
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
    protected static function saveKeyFile($filePath, $keyData)
    {
        return \file_put_contents(
            $filePath,
            \Sodium\bin2hex(
                Halite::HALITE_VERSION_KEYS . $keyData .
                \Sodium\crypto_generichash(
                    Halite::HALITE_VERSION_KEYS . $keyData,
                    null,
                    \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                )
            )
        );
    }
}
