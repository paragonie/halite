<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Contract\CryptoKeyInterface;
use \ParagonIE\Halite\Symmetric\EncryptionKey;
use \ParagonIE\Halite\Symmetric\Crypto;
use \ParagonIE\Halite\Alerts\InvalidMessage;

class Cookie 
{
    protected $key;
    
    public function __construct(CryptoKeyInterface $key)
    {
        if (!($key instanceof EncryptionKey)) {
            throw new \ParagonIE\Halite\Alerts\InvalidKey(
                'Argument 1: Expected an instance of EncryptionKey'
            );
        }
        $this->key = $key;
    }
    /**
     * Hide this from var_dump(), etc.
     * 
     * @return array
     */
    public function __debugInfo()
    {
        return [
            'key' => 'private'
        ];
    }
    
    /**
     * Store a value in an encrypted cookie
     * 
     * @param string $name
     * @return mixed (typically an array)
     */
    public function fetch($name)
    {
        if (!isset($_COOKIE[$name])) {
            return null;
        }
        try {
            $decrypted = Crypto::decrypt($_COOKIE[$name], $this->key);
            if (empty($decrypted)) {
                return null;
            }
            return \json_decode($decrypted, true);
        } catch (InvalidMessage $e) {
            return;
        }
    }
    
    /**
     * Store a value in an encrypted cookie
     * 
     * @param string $name
     * @param mixed $value
     * @param int $expire    (defaults to 0)
     * @param string $path   (defaults to '/')
     * @param string $domain (defaults to NULL)
     * @param bool $secure   (defaults to TRUE)
     * @param bool $httponly (defaults to TRUE)
     * @return bool
     */
    public function store(
        $name,
        $value,
        $expire = 0,
        $path = '/',
        $domain = null,
        $secure = true,
        $httponly = true
    ) {
        return \setcookie(
            $name,
            Crypto::encrypt(
                \json_encode($value),
                $this->key
            ),
            $expire,
            $path,
            $domain,
            $secure,
            $httponly
        );
    }
}
