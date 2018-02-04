<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\{
    Base32,
    Base32Hex,
    Base64,
    Base64UrlSafe,
    Hex
};
use ParagonIE\Halite\Alerts\InvalidType;

/**
 * Class Halite
 *
 * This is just an final class that hosts some constants
 *
 * Version Tag Info:
 *
 *  \x31\x41 => 3.141 (approx. pi)
 *  \x31\x42 => 3.142 (approx. pi)
 *  Because pi is the symbol we use for Paragon Initiative Enterprises
 *  \x00\x07 => version 0.07
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
final class Halite
{
    const VERSION              = '4.4.0';

    const HALITE_VERSION_KEYS  = "\x31\x40\x04\x00";
    const HALITE_VERSION_FILE  = "\x31\x41\x04\x00";
    const HALITE_VERSION       = "\x31\x42\x04\x00";

    /* Raw bytes (decoded) of the underlying ciphertext */
    const VERSION_TAG_LEN      = 4;
    const VERSION_PREFIX       = 'MUIEA';
    const VERSION_OLD_PREFIX   = 'MUIDA';

    const ENCODE_HEX           = 'hex';
    const ENCODE_BASE32        = 'base32';
    const ENCODE_BASE32HEX     = 'base32hex';
    const ENCODE_BASE64        = 'base64';
    const ENCODE_BASE64URLSAFE = 'base64urlsafe';

    /**
     * Don't allow this to be instantiated.
     *
     * @throws \Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Select which encoding/decoding function to use.
     *
     * @internal
     * @param mixed $chosen
     * @param bool $decode
     * @return callable|null
     * @throws InvalidType
     */
    public static function chooseEncoder($chosen, bool $decode = false)
    {
        if ($chosen === true) {
            return null;
        } elseif ($chosen === false) {
            return \implode(
                '::',
                [
                    Hex::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE32) {
            return \implode(
                '::',
                [
                    Base32::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE32HEX) {
            return \implode(
                '::',
                [
                    Base32Hex::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE64) {
            return \implode(
                '::',
                [
                    Base64::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE64URLSAFE) {
            return \implode(
                '::',
                [
                    Base64UrlSafe::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        } elseif ($chosen === self::ENCODE_HEX) {
            return \implode(
                '::',
                [
                    Hex::class,
                    $decode ? 'decode' : 'encode'
                ]
            );
        }
        throw new InvalidType(
            'Illegal value for encoding choice.'
        );
    }

    /**
     * Is Libsodium set up correctly? Use this to verify that you can use the
     * newer versions of Halite correctly.
     *
     * @param bool $echo
     * @return bool
     * @codeCoverageIgnore
     */
    public static function isLibsodiumSetupCorrectly(bool $echo = false): bool
    {
        if (!\extension_loaded('sodium')) {
            if ($echo) {
                echo "You do not have the sodium extension enabled.\n";
            }
            return false;
        }

        // Require libsodium 1.0.15
        $major = \SODIUM_LIBRARY_MAJOR_VERSION;
        if ($major < 10) {
            if ($echo) {
                echo 'Halite needs libsodium 1.0.15 or higher. You have: ',
                \SODIUM_LIBRARY_VERSION, "\n";
            }
            return false;
        }
        return true;
    }
}
