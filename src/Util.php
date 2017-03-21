<?php
declare(strict_types = 1);
namespace ParagonIE\Halite;

use ParagonIE\Halite\Alerts\{
    CannotPerformOperation, InvalidDigestLength, InvalidType
};

/**
 * Class Util
 *
 * Various useful utilities, used within Halite and available for general use
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 */
final class Util
{
    /**
     * Don't allow this to be instantiated.
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Wrapper around \Sodium\crypto_generichash()
     *
     * Returns hexadecimal characters.
     *
     * @param string $input
     * @param int    $length
     * @return string
     */
    public static function hash(
        string $input,
        int $length = \Sodium\CRYPTO_GENERICHASH_BYTES
    ): string {
        return \Sodium\bin2hex(
            self::raw_keyed_hash($input, '', $length)
        );
    }

    /**
     * Wrapper around \Sodium\crypto_generichash()
     *
     * Returns raw binary.
     *
     * @param string $input
     * @param int    $length
     * @return string
     */
    public static function raw_hash(
        string $input,
        int $length = \Sodium\CRYPTO_GENERICHASH_BYTES
    ): string {
        return self::raw_keyed_hash($input, '', $length);
    }

    /**
     * Use a derivative of HKDF to derive multiple keys from one.
     * http://tools.ietf.org/html/rfc5869
     *
     * This is a variant from hash_hkdf() and instead uses BLAKE2b provided by
     * libsodium.
     *
     * Important: instead of a true HKDF (from HMAC) construct, this uses the
     * \Sodium\crypto_generichash() key parameter. This is *probably* okay.
     *
     * @param string $ikm Initial Keying Material
     * @param int    $length How many bytes?
     * @param string $info What sort of key are we deriving?
     * @param string $salt
     * @return string
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     */
    public static function hkdfBlake2b(
        string $ikm,
        int $length,
        string $info = '',
        string $salt = ''
    ): string {
        // Sanity-check the desired output length.
        if ($length < 0 || $length > (255 * \Sodium\CRYPTO_GENERICHASH_KEYBYTES)) {
            throw new InvalidDigestLength(
                'Argument 2: Bad HKDF Digest Length'
            );
        }
        // "If [salt] not provided, is set to a string of HashLen zeroes."
        if (empty($salt)) {
            $salt = \str_repeat("\x00", \Sodium\CRYPTO_GENERICHASH_KEYBYTES);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = self::raw_keyed_hash($ikm, $salt);

        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        if (self::safeStrlen($prk) < \Sodium\CRYPTO_GENERICHASH_KEYBYTES) {
            throw new CannotPerformOperation(
                'An unknown error has occurred'
            );
        }
        // T(0) = ''
        $t          = '';
        $last_block = '';
        for ($block_index = 1; self::safeStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = self::raw_keyed_hash(
                $last_block . $info . \chr($block_index),
                $prk
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }
        // ORM = first L octets of T
        $orm = self::safeSubstr($t, 0, $length);
        if ($orm === false) {
            throw new CannotPerformOperation(
                'An unknown error has occurred'
            );
        }
        return $orm;
    }

    /**
     * Wrapper around \Sodium\crypto_generichash()
     *
     * Expects a key (binary string).
     * Returns hexadecimal characters.
     *
     * @param string $input
     * @param string $key
     * @param int    $length
     * @return string
     */
    public static function keyed_hash(
        string $input,
        string $key,
        int $length = \Sodium\CRYPTO_GENERICHASH_BYTES
    ): string {
        return \Sodium\bin2hex(
            self::raw_keyed_hash($input, $key, $length)
        );
    }

    /**
     * Wrapper around \Sodium\crypto_generichash()
     *
     * Expects a key (binary string).
     * Returns raw binary.
     *
     * @param string $input
     * @param string $key
     * @param int    $length
     * @return string
     * @throws CannotPerformOperation
     */
    public static function raw_keyed_hash(
        string $input,
        string $key,
        int $length = \Sodium\CRYPTO_GENERICHASH_BYTES
    ): string {
        if ($length < \Sodium\CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new CannotPerformOperation(
                \sprintf(
                    'Output length must be at least %d bytes.',
                    \Sodium\CRYPTO_GENERICHASH_BYTES_MIN
                )
            );
        }
        if ($length > \Sodium\CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new CannotPerformOperation(
                \sprintf(
                    'Output length must be at most %d bytes.',
                    \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                )
            );
        }
        return \Sodium\crypto_generichash($input, $key, $length);
    }

    /**
     * Safe string length
     *
     * @ref mbstring.func_overload
     *
     * @static bool $exists
     * @param string $str
     * @return int
     * @throws CannotPerformOperation
     */
    public static function safeStrlen(string $str): int
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \is_callable('\\mb_strlen');
        }

        if ($exists) {
            $length = \mb_strlen($str, '8bit');
            if ($length === false) {
                throw new CannotPerformOperation(
                    'mb_strlen() failed unexpectedly'
                );
            }
        } else {
            // If we reached here, we can rely on strlen to count bytes:
            $length = \strlen($str);
            if ($length === false) {
                throw new CannotPerformOperation(
                    'strlen() failed unexpectedly'
                );
            }
        }
        return $length;
    }

    /**
     * Safe substring
     *
     * @ref mbstring.func_overload
     *
     * @static bool $exists
     * @param string $str
     * @param int    $start
     * @param int    $length
     * @return string
     * @throws InvalidType
     */
    public static function safeSubstr(
        string $str,
        int $start = 0,
        $length = null
    ): string {
        static $exists = null;
        if ($exists === null) {
            $exists = \is_callable('\\mb_substr');
        }
        if ($exists) {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if ($length === null) {
                if ($start >= 0) {
                    $length = self::safeStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            } elseif (!\is_int($length)) {
                throw new InvalidType(
                    'Argument 3: integer expected'
                );
            }
            // $length calculation above might result in a 0-length string
            if ($length === 0 || $start > self::safeStrlen($str)) {
                return '';
            }
            return \mb_substr($str, $start, $length, '8bit');
        }
        if ($length === 0) {
            return '';
        }
        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if ($length !== null) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }

    /**
     * PHP 7 uses interned strings. We don't want altering this one to alter
     * the original string.
     *
     * @param string $string
     * @return string
     * @throws CannotPerformOperation
     */
    public static function safeStrcpy(string $string): string
    {
        $length = self::safeStrlen($string);
        $return = '';
        for ($i = 0; $i < $length; ++$i) {
            $return .= $string[$i];
        }
        return $return;
    }

    /**
     * Calculate A xor B, given two binary strings of the same length.
     *
     * Uses pack() and unpack() to avoid cache-timing leaks caused by
     * chr().
     *
     * @param string $left
     * @param string $right
     * @return string
     * @throws InvalidType
     */
    public static function xorStrings(string $left, string $right): string
    {
        $length = self::safeStrlen($left);
        if ($length !== self::safeStrlen($right)) {
            throw new InvalidType(
                'Both strings must be the same length'
            );
        }
        if ($length < 1) {
            return '';
        }

        /**
         * @var int[]
         */
        $leftInt = \unpack('C*', $left);

        /**
         * @var int[]
         */
        $rightInt = \unpack('C*', $right);

        $output = '';
        for ($i = 0; $i < $length; ++$i) {
            $output .= \pack(
                'C',
                (($leftInt[$i + 1] ^ $rightInt[$i + 1]) & 0xff)
            );
        }
        return $output;
    }
}
