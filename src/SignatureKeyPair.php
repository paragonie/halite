<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\Alerts as CryptoException;

/**
 * Describes a pair of secret and public keys
 */
class SignatureKeyPair extends KeyPair
{
    /**
     * Hide this from var_dump(), etc.
     * 
     * @return array
     */
    public function __debugInfo()
    {
        return [
            'privateKey' => '**protected**',
            'publicKey' => '**protected**'
        ];
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
        $type = self::CRYPTO_BOX
    ) { 
        if (Key::doesNotHaveFlag($type, Key::ASYMMETRIC)) {
            throw new CryptoException\InvalidKey(
                'An asymmetric key type must be passed to KeyPair::generate()'
            );
        }
        if (Key::hasFlag($type, Key::SIGNATURE)) {
            $key = SignatureSecretKey::deriveFromPassword($password, $salt, Key::CRYPTO_SIGN);
            $keypair = new KeyPair(...$key);
            return $keypair;
        }
        throw new CryptoException\InvalidKey(
            'You must specify encryption or authentication flags.'
        );
    }
    
    /**
     * Generate a new keypair
     * 
     * @param int $type Key flags
     * @param &string $secret_key - Reference to optional variable to store secret key in
     * @return KeyPair
     * @throws CryptoException\InvalidKey
     */
    public static function generate($type = Key::CRYPTO_SIGN, &$secret_key = null)
    {
        if (Key::doesNotHaveFlag($type, Key::ASYMMETRIC)) {
            throw new CryptoException\InvalidKey(
                'An asymmetric key type must be passed to KeyPair::generate()'
            );
        }
        if (Key::hasFlag($type, Key::SIGNATURE)) {
            $key = SignatureSecretKey::generate(Key::CRYPTO_SIGN, $secret_key);
            $keypair = new KeyPair(...$key);
            return $keypair;
        }
        throw new CryptoException\InvalidKey(
            'You must specify encryption or authentication flags.'
        );
    }
    
    /**
     * Get a Key object for the public key
     * 
     * @return Key
     */
    public function getPublicKey()
    {
       return $this->public_key;
    }
    
    /**
     * Get a Key object for the secret key
     * 
     * @return Key
     */
    public function getSecretKey()
    {
       return $this->secret_key;
    }
    
    /**
     * Load a keypair from a file
     * 
     * @param string $filePath
     * @param int $type
     * @return KeyPair
     * 
     * @throws CryptoException\InvalidFlags
     */
    public static function fromFile(
        $filePath,
        $type = Key::CRYPTO_BOX
    ) {
        $keys = Key::fromFile(
            $filePath,
            ($type | Key::ASYMMETRIC | Key::ENCRYPTION)
        );
        return new KeyPair(...$keys);
    }
    
    /**
     * Save a copy of the secret key to a file
     *
     * @param string $filePath
     * @return bool|int
     */
    public function saveToFile($filePath)
    {
        return $this->secret_key->saveToFile($filePath);
    }
}
