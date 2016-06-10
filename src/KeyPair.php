<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Asymmetric\{
    PublicKey,
    SecretKey
};

/**
 * Describes a pair of secret and public keys
 */
class KeyPair
{
    /**
     * @var SecretKey
     */
    protected $secret_key;

    /**
     * @var PublicKey
     */
    protected $public_key;

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
     * @return PublicKey
     */
    public function getPublicKey()
    {
       return $this->public_key;
    }

    /**
     * Get a Key object for the secret key
     * 
     * @return SecretKey
     */
    public function getSecretKey()
    {
       return $this->secret_key;
    }
}
