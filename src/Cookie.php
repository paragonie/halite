<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Halite\{
    Alerts\InvalidMessage,
    Symmetric\Config as SymmetricConfig,
    Symmetric\Crypto,
    Symmetric\EncryptionKey
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
            $stored = $_COOKIE[$name];
            $config = self::getConfig($stored);
            $decrypted = Crypto::decrypt(
                $stored,
                $this->key,
                $config->ENCODING
            );
            if (empty($decrypted)) {
                return null;
            }
            return \json_decode($decrypted, true);
        } catch (InvalidMessage $e) {
            return null;
        }
    }

    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   A stored password hash
     * @return SymmetricConfig
     * @throws InvalidMessage
     */
    protected static function getConfig(string $stored): SymmetricConfig
    {
        $length = Util::safeStrlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new InvalidMessage(
                'Encrypted password hash is way too short.'
            );
        }
        if (\hash_equals(Util::safeSubstr($stored, 0, 5), Halite::VERSION_PREFIX)) {
            return SymmetricConfig::getConfig(
                Base64UrlSafe::decode($stored),
                'encrypt'
            );
        }
        $v = \Sodium\hex2bin(Util::safeSubstr($stored, 0, 8));
        return SymmetricConfig::getConfig($v, 'encrypt');
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
                new HiddenString(\json_encode($value)),
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
