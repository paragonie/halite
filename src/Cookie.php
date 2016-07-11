<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\{
    Alerts\InvalidMessage,
    Symmetric\EncryptionKey,
    Symmetric\Crypto
};

/**
 * Class Cookie
 *
 * Secure encrypted cookies
 *
 * @package ParagonIE\Halite
 */
final class Cookie 
{
    /**
     * @var EncryptionKey
     */
    protected $key;

    /**
     * Cookie constructor.
     * @param EncryptionKey $key
     */
    public function __construct(EncryptionKey $key)
    {
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
    public function fetch(string $name)
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
            return null;
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
     * @param bool $httpOnly (defaults to TRUE)
     * @return bool
     */
    public function store(
        string $name,
        $value,
        int $expire = 0,
        string $path = '/',
        string $domain = '',
        bool $secure = true,
        bool $httpOnly = true
    ): bool {
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
            $httpOnly
        );
    }
}
