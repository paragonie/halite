<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\{
    Config as BaseConfig,
    Halite,
    Util
};

/**
 * Class Config
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class Config extends BaseConfig
{
    /**
     * Get the configuration
     *
     * @param string $header
     * @param string $mode
     * @return self
     *
     * @throws InvalidMessage
     */
    public static function getConfig(
        string $header,
        string $mode = 'encrypt'
    ): self {
        if (Binary::safeStrlen($header) < Halite::VERSION_TAG_LEN) {
            throw new InvalidMessage(
                'Invalid version tag'
            );
        }
        /*
         * We can safely omit the check on the first two bytes since
         * this is checked elsewhere. This is just a best-effort to
         * obtain the asymmetric configuration
         */
        $major = Util::chrToInt($header[2]);
        $minor = Util::chrToInt($header[3]);
        if ($mode === 'encrypt') {
            return new Config(
                self::getConfigEncrypt($major, $minor)
            );
        }
        throw new InvalidMessage(
            'Invalid configuration mode: '.$mode
        );
    }

    /**
     * Get the configuration for encrypt operations
     *
     * @param int $major
     * @param int $minor
     * @return array
     * @throws InvalidMessage
     */
    public static function getConfigEncrypt(int $major, int $minor): array
    {
        if ($major === 5) {
            switch ($minor) {
                case 0:
                    return [
                        'ENCODING' => Halite::ENCODE_BASE64URLSAFE,
                        'HASH_DOMAIN_SEPARATION' => 'HaliteVersion5X25519SharedSecret',
                        'HASH_SCALARMULT' => true,
                    ];
            }
        }
        if ($major === 4 || $major === 3) {
            switch ($minor) {
                case 0:
                    return [
                        'ENCODING' => Halite::ENCODE_BASE64URLSAFE,
                        'HASH_DOMAIN_SEPARATION' => '',
                        'HASH_SCALARMULT' => false,
                    ];
            }
        }
        throw new InvalidMessage(
            'Invalid version tag'
        );
    }
}
