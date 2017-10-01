<?php
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts as CryptoException;

/**
 * Encapsulates the configuration for a specific version of Halite
 */
class Config
{
    /** @var array */
    private $config;
    
    public function __construct(array $set = [])
    {
        $this->config = $set;
    }
    
    /**
     * Getter
     * 
     * @param string $key
     * @return mixed
     * @throws CryptoException\ConfigDirectiveNotFound
     */
    public function __get($key)
    {
        if (\array_key_exists($key, $this->config)) {
            return $this->config[$key];
        }
        throw new CryptoException\ConfigDirectiveNotFound($key);
    }
    
    /**
     * Setter (NOP)
     * 
     * @param mixed $key
     * @param mixed $value
     */
    public function __set($key, $value = null)
    {
        return false;
    }
}