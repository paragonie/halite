<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength,
    InvalidMessage,
    InvalidSignature,
    InvalidType
};
use ParagonIE\Halite\Symmetric\{
    Config as SymmetricConfig,
    Crypto,
    EncryptionKey
};
use ParagonIE\HiddenString\HiddenString;
use SodiumException;
use TypeError;
use function
    hash_equals,
    is_string,
    json_decode,
    json_encode,
    setcookie;

/**
 * Class Cookie
 *
 * Secure encrypted cookies
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref https://www.php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/en-US/MPL/2.0/.
 *
 * @codeCoverageIgnore
 */
final class Cookie 
{
    protected EncryptionKey $key;

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
    public function __debugInfo(): array
    {
        return [
            'key' => 'private'
        ];
    }

    /**
     * Fetch a value from an encrypted cookie
     *
     * @param string $name
     *
     * @return mixed|null (typically an array)
     *
     * @throws InvalidDigestLength
     * @throws InvalidSignature
     * @throws CannotPerformOperation
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     */
    public function fetch(
        #[\SensitiveParameter]
        string $name
    ) {
        if (!isset($_COOKIE[$name])) {
            return null;
        }
        try {
            /** @var string|array|int|float|bool $stored */
            $stored = $_COOKIE[$name];
            if (!is_string($stored)) {
                throw new InvalidType('Cookie value is not a string');
            }
            $config = self::getConfig($stored);
            $encoding = $config->ENCODING;
            $decrypted = Crypto::decrypt(
                $stored,
                $this->key,
                $encoding
            );
            return json_decode($decrypted->getString(), true);
        } catch (InvalidMessage $e) {
            return null;
        }
    }

    /**
     * Get the configuration for this version of halite
     *
     * @param string $stored   A stored password hash
     * @return SymmetricConfig
     *
     * @throws InvalidMessage
     * @throws TypeError
     */
    protected static function getConfig(string $stored): SymmetricConfig
    {
        $length = Binary::safeStrlen($stored);
        // This doesn't even have a header.
        if ($length < 8) {
            throw new InvalidMessage(
                'Encrypted password hash is way too short.'
            );
        }
        if (hash_equals(Binary::safeSubstr($stored, 0, 5), Halite::VERSION_PREFIX)) {
            $decoded = Base64UrlSafe::decode($stored);
            return SymmetricConfig::getConfig(
                $decoded,
                'encrypt'
            );
        }
        $v = Hex::decode(Binary::safeSubstr($stored, 0, 8));
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
     * @param string $sameSite (defaults to ''; PHP >= 7.3.0)
     *
     * @return bool
     *
     * @throws InvalidDigestLength
     * @throws CannotPerformOperation
     * @throws InvalidMessage
     * @throws InvalidType
     * @throws SodiumException
     * @throws TypeError
     *
     * @psalm-suppress InvalidArgument  PHP version incompatibilities
     * @psalm-suppress MixedArgument
     */
    public function store(
        #[\SensitiveParameter]
        string $name,
        #[\SensitiveParameter]
        $value,
        int $expire = 0,
        string $path = '/',
        string $domain = '',
        bool $secure = true,
        bool $httpOnly = true,
        string $sameSite = ''
    ): bool {
        $val = Crypto::encrypt(
            new HiddenString(
                (string) json_encode($value)
            ),
            $this->key
        );
        $options = [
            'expires' => (int) $expire,
            'path' => (string) $path,
            'domain' => (string) $domain,
            'secure' => (bool) $secure,
            'httponly' => (bool) $httpOnly,
        ];
        if ($sameSite !== '') {
            $options['samesite'] = (string) $sameSite;
        }
        return setcookie(
            $name,
            $val,
            $options
        );
    }
}
