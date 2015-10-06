<?php
namespace ParagonIE\Halite;

use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Symmetric;

class Cookie 
{
    protected $key;
    
    public function __construct(Key $key)
    {
        $this->key = $key;
        \Sodium\memzero($key);
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
        $decrypted = Symmetric::decrypt($_COOKIE[$name], $this->key);
        if (empty($decrypted)) {
            return null;
        }
        return \json_decode($decrypted, true);
    }
    
    /**
     * Store a value in an encrypted cookie
     * 
     * @param string $name
     * @param mixed $value
     * @param int $expire
     * @param string $path
     * @param string $domain
     * @param bool $secure
     * @param bool $httponly
     * @return bool
     */
    public function store(
        $name,
        $value,
        $expire = 0,
        $path = '/',
        $domain = null,
        $secure = null,
        $httponly = null
    ) {
        return \setcookie(
            $name,
            Symmetric::encrypt(
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
