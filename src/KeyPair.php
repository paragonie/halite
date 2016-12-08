<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Asymmetric\{
    PublicKey,
    SecretKey
};

/**
 * Class KeyPair
 *
 * Describes a pair of secret and public keys
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 */
class KeyPair
{
    /**
     * @var SecretKey
     */
    protected $secretKey;

    /**
     * @var PublicKey
     */
    protected $publicKey;

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
       return $this->publicKey;
    }

    /**
     * Get a Key object for the secret key
     * 
     * @return SecretKey
     */
    public function getSecretKey()
    {
       return $this->secretKey;
    }
}
