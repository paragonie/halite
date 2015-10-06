<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Asymmetric\PublicKey;
use ParagonIE\Halite\Asymmetric\SecretKey;
use ParagonIE\Halite\Alerts as CryptoException;

/**
 * Describes a pair of secret and public keys
 */
class KeyPair
{
    private    $secret_key;
    protected  $public_key;
    
    /**
     * 
     * Pass it a secret key, it will automatically generate a public key
     * 
     * @param ...Key $keys
     */
    public function __construct(Key ...$keys)
    {
        switch (\count($keys)) {
            case 2:
                if ($keys[0]->isPublicKey()) {
                    if ($keys[1]->isPublicKey()) {
                        throw new CryptoException\InvalidKey(
                            'Both keys cannot be public keys'
                        );
                    }
                    // $keys[0] is public, $keys[1] is secret
                    $this->secret_key = $keys[1] instanceof SecretKey
                        ? $keys[1]
                        : new SecretKey(
                            $keys[1]->get(),
                            $keys[1]->isSigningKey()
                        );
                    
                    /**
                     * Let's use the secret key to calculate the *correct* 
                     * public key. We're effectively discarding $keys[0] but
                     * this ensures correct usage down the line.
                     */
                    if ($this->secret_key->isSigningKey()) {
                        // crypto_sign - Ed25519
                        $pub = \Sodium\crypto_sign_publickey_from_secretkey(
                            $keys[1]->get()
                        );
                        $this->public_key = new PublicKey($pub, true);
                        \Sodium\memzero($pub);
                    } else {
                        // crypto_box - Curve25519
                        $pub = \Sodium\crypto_box_publickey_from_secretkey(
                            $keys[1]->get()
                        );
                        $this->public_key = new PublicKey($pub, false);
                        \Sodium\memzero($pub);
                    }
                    
                } elseif ($keys[1]->isPublicKey()) {
                    // We can deduce that $keys[0] is a secret key
                    $this->secret_key = $keys[0] instanceof SecretKey
                        ? $keys[0]
                        : new SecretKey(
                            $keys[0]->get(),
                            $keys[0]->isSigningKey()
                        );
                    
                    /**
                     * Let's use the secret key to calculate the *correct* 
                     * public key. We're effectively discarding $keys[0] but
                     * this ensures correct usage down the line.
                     */
                    if ($this->secret_key->isSigningKey()) {
                        // crypto_sign - Ed25519
                        $pub = \Sodium\crypto_sign_publickey_from_secretkey(
                            $keys[0]->get()
                        );
                        $this->public_key = new PublicKey($pub, true);
                    } else {
                        // crypto_box - Curve25519
                        $pub = \Sodium\crypto_box_publickey_from_secretkey(
                            $keys[0]->get()
                        );
                        $this->public_key = new PublicKey($pub, false);
                        \Sodium\memzero($pub);
                    }
                } else {
                    throw new CryptoException\InvalidKey(
                        'Both keys cannot be secret keys'
                    );
                }
                break;
            case 1:
                if ($keys[0]->isPublicKey()) {
                    throw new CryptoException\InvalidKey(
                        'We cannot generate a valid keypair given only a public key; we can given only a secret key, however.'
                    );
                }
                $this->secret_key = $keys[0] instanceof SecretKey
                    ? $keys[0]
                    : new SecretKey(
                        $keys[0]->get(),
                        $keys[0]->isSigningKey()
                    );
                
                if ($this->secret_key->isSigningKey()) {
                    // We need to calculate the public key from the secret key
                    $pub = \Sodium\crypto_sign_publickey_from_secretkey(
                        $keys[0]->get()
                    );
                    $this->public_key = new PublicKey($pub, true);
                    \Sodium\memzero($pub);
                } else {
                    // We need to calculate the public key from the secret key
                    $pub = \Sodium\crypto_box_publickey_from_secretkey(
                        $keys[0]->get()
                    );
                    $this->public_key = new PublicKey($pub, false);
                    \Sodium\memzero($pub);
                }
                break;
            default:
                throw new \InvalidArgumentException(
                    'Halite\\Keypair expects 1 or 2 keys'
                );
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
        $type = self::CRYPTO_BOX
    ) {
        
        if (($type & Key::ASYMMETRIC) === 0) {
            throw new CryptoException\InvalidKey(
                'An asymmetric key type must be passed to KeyPair::generate()'
            );
        }
        if (($type & Key::ENCRYPTION) !== 0) {
            return Key::deriveFromPassword($password, $salt, Key::CRYPTO_BOX);
        } elseif (($type & Key::SIGNATURE) !== 0) {
            return Key::deriveFromPassword($password, $salt, Key::CRYPTO_SIGN);
        }
        throw new CryptoException\InvalidKey(
            'You must specify encryption or authentication flags.'
        );
    }
    
    /**
     * Generate a new keypair
     * 
     * @param int $type Key flags
     * @return array [Key $secret, Key $public]
     * @throws CryptoException\InvalidKey
     */
    public static function generate($type = Key::CRYPTO_BOX)
    {
        if (($type & Key::ASYMMETRIC) === 0) {
            throw new CryptoException\InvalidKey(
                'An asymmetric key type must be passed to KeyPair::generate()'
            );
        }
        if (($type & Key::ENCRYPTION) !== 0) {
            return Key::generate(Key::CRYPTO_BOX);
        } elseif (($type & Key::SIGNATURE) !== 0) {
            return Key::generate(Key::CRYPTO_SIGN);
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
}
