<?php
declare(strict_types = 1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\{
    Base32, Base32Hex, Base64, Base64UrlSafe, Hex
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
 */
final class Halite
{
    const VERSION = '3.0.0';

    const HALITE_VERSION_KEYS = "\x31\x40\x03\x00";

    const HALITE_VERSION_FILE = "\x31\x41\x03\x00";

    const HALITE_VERSION = "\x31\x42\x03\x00";

    const VERSION_TAG_LEN = 4;

    const VERSION_PREFIX = 'MUIDA';

    const ENCODE_HEX = 'hex';

    const ENCODE_BASE32 = 'base32';

    const ENCODE_BASE32HEX = 'base32hex';

    const ENCODE_BASE64 = 'base64';

    const ENCODE_BASE64URLSAFE = 'base64urlsafe';

    /**
     * Don't allow this to be instantiated.
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
     * @param bool  $decode
     * @return callable (array or string)
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
                    $decode ? 'decode' : 'encode',
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE32) {
            return \implode(
                '::',
                [
                    Base32::class,
                    $decode ? 'decode' : 'encode',
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE32HEX) {
            return \implode(
                '::',
                [
                    Base32Hex::class,
                    $decode ? 'decode' : 'encode',
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE64) {
            return \implode(
                '::',
                [
                    Base64::class,
                    $decode ? 'decode' : 'encode',
                ]
            );
        } elseif ($chosen === self::ENCODE_BASE64URLSAFE) {
            return \implode(
                '::',
                [
                    Base64UrlSafe::class,
                    $decode ? 'decode' : 'encode',
                ]
            );
        } elseif ($chosen === self::ENCODE_HEX) {
            return \implode(
                '::',
                [
                    Hex::class,
                    $decode ? 'decode' : 'encode',
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
     */
    public static function isLibsodiumSetupCorrectly(bool $echo = false): bool
    {
        // Require libsodium 1.0.9
        $major = \Sodium\library_version_major();
        $minor = \Sodium\library_version_minor();
        if ($major < 9 || ($major === 9 && $minor < 2)) {
            if ($echo) {
                echo 'Halite needs libsodium 1.0.9 or higher. You have: ',
                \Sodium\version_string(), "\n";
            }
            return false;
        }

        // Added in version 1.0.3 of the PHP extension
        if (!\is_callable('\\Sodium\\crypto_pwhash_str')) {
            if ($echo) {
                echo 'Halite needs version 1.0.6 or higher of the PHP extension installed.', "\n";
            }
            return false;
        }

        if (!\is_callable('\\Sodium\\crypto_box_seal')) {
            if ($echo) {
                echo 'crypto_box_seal() is not available.', "\n";
            }
            return false;
        }

        return true;
    }
}
