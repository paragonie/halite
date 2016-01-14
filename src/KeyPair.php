<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Asymmetric\{
    EncryptionPublicKey,
    EncryptionSecretKey,
    SignaturePublicKey,
    SignatureSecretKey
};
use \ParagonIE\Halite\Alerts as CryptoException;

/**
 * Describes a pair of secret and public keys
 */
class KeyPair
{
    protected  $secret_key;
    protected  $public_key;

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
