<?php
namespace ParagonIE\Halite\Primitive;

use ParagonIE\Halite\Alerts\Crypto as CryptoAlert;

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
                        throw new CryptoAlert\InvalidKey(
                            'Both keys cannot be public keys'
                        );
                    }
                    // $keys[0] is public, $keys[1] is secret
                    $this->secret_key = $keys[1];
                    
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
                        $this->public_key = new Key($pub, true, true, true);
                        \Sodium\memzero($pub);
                    } else {
                        // crypto_box - Curve25519
                        $pub = \Sodium\crypto_box_publickey_from_secretkey(
                            $keys[1]->get()
                        );
                        $this->public_key = new Key($pub, true, false, true);
                        \Sodium\memzero($pub);
                    }
                    
                } elseif ($keys[1]->isPublicKey()) {
                    // We can deduce that $keys[0] is a secret key
                    $this->secret_key = $keys[0];
                    
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
                        $this->public_key = new Key($pub, true, true, true);
                    } else {
                        // crypto_box - Curve25519
                        $pub = \Sodium\crypto_box_publickey_from_secretkey(
                            $keys[0]->get()
                        );
                        $this->public_key = new Key($pub, true, false, true);
                        \Sodium\memzero($pub);
                    }
                } else {
                    throw new CryptoAlert\InvalidKey(
                        'Both keys cannot be secret keys'
                    );
                }
                break;
            case 1:
                if ($keys[0]->isPublicKey()) {
                    throw new CryptoAlert\InvalidKey(
                        'We cannot generate a valid keypair given only a public key; we can given only a secret key, however.'
                    );
                }
                $this->secret_key = $keys[0];
                
                if ($this->secret_key->isSigningKey()) {
                    // We need to calculate the public key from the secret key
                    $pub = \Sodium\crypto_sign_publickey_from_secretkey(
                        $keys[0]->get()
                    );
                    $this->public_key = new Key($pub, true, true, true);
                    \Sodium\memzero($pub);
                } else {
                    // We need to calculate the public key from the secret key
                    $pub = \Sodium\crypto_box_publickey_from_secretkey(
                        $keys[0]->get()
                    );
                    $this->public_key = new Key($pub, true, false, true);
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
