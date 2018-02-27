<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\ConfigDirectiveNotFound;

/**
 * Class Config
 *
 * Encapsulates the configuration for a specific version of Halite
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
class Config
{
    /**
     * @var array
     */
    private $config;

    /**
     * Config constructor.
     * @param array $set
     */
    public function __construct(array $set = [])
    {
        $this->config = $set;
    }
    
    /**
     * Getter
     *
     * @param string $key
     * @return mixed
     * @throws ConfigDirectiveNotFound
     */
    public function __get(string $key)
    {
        if (\array_key_exists($key, $this->config)) {
            return $this->config[$key];
        }
        throw new ConfigDirectiveNotFound($key);
    }
    
    /**
     * Setter (NOP)
     * 
     * @param string $key
     * @param mixed $value
     * @return bool
     * @codeCoverageIgnore
     */
    public function __set(string $key, $value = null)
    {
        return false;
    }
}
