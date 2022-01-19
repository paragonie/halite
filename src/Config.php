<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\ConfigDirectiveNotFound;
use function array_key_exists;

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
 *
 * @property string|bool ENCODING
 *
 * AsymmetricCrypto:
 * @property string HASH_DOMAIN_SEPARATION
 * @property bool HASH_SCALARMULT
 *
 * SymmetricCrypto:
 * @property bool CHECKSUM_PUBKEY
 * @property int BUFFER
 * @property int HASH_LEN
 * @property int SHORTEST_CIPHERTEXT_LENGTH
 * @property int NONCE_BYTES
 * @property int HKDF_SALT_LEN
 * @property string ENC_ALGO
 * @property string MAC_ALGO
 * @property int MAC_SIZE
 * @property int PUBLICKEY_BYTES
 * @property bool HKDF_USE_INFO
 * @property string HKDF_SBOX
 * @property string HKDF_AUTH
 * @property bool USE_PAE
 */
class Config
{
    /**
     * @var array
     */
    private array $config;

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
        if (array_key_exists($key, $this->config)) {
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
    public function __set(string $key, mixed $value = null)
    {
        return false;
    }
}
