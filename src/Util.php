<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use ParagonIE\ConstantTime\{
    Binary,
    Hex
};
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength,
    InvalidType
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
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class Util
{
    /**
     * Don't allow this to be instantiated.
     * @throws \Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new \Error('Do not instantiate');
    }

    /**
     * Convert a character to an integer (without cache-timing side-channels)
     *
     * @param string $chr
     * @return int
     * @throws \RangeException
     */
    public static function chrToInt(string $chr): int
    {
        if (Binary::safeStrlen($chr) !== 1) {
            throw new \RangeException('Must be a string with a length of 1');
        }
        $result = \unpack('C', $chr);
        return (int) $result[1];
    }

    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Returns hexadecimal characters.
     *
     * @param string $input
     * @param int $length
     * @return string
     * @throws CannotPerformOperation
     * @throws \SodiumException
     * @throws \TypeError
     */
    public static function hash(
        string $input,
        int $length = \SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        return Hex::encode(
            self::raw_keyed_hash($input, '', $length)
        );
    }

    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Returns raw binary.
     *
     * @param string $input
     * @param int $length
     * @return string
     * @throws CannotPerformOperation
     * @throws \SodiumException
     */
    public static function raw_hash(
        string $input,
        int $length = \SODIUM_CRYPTO_GENERICHASH_BYTES
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
     * crypto_generichash() key parameter. This is *probably* okay.
     * 
     * @param string $ikm Initial Keying Material
     * @param int $length How many bytes?
     * @param string $info What sort of key are we deriving?
     * @param string $salt
     * @return string
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws \TypeError
     * @throws \SodiumException
     */
    public static function hkdfBlake2b(
        string $ikm,
        int $length,
        string $info = '',
        string $salt = ''
    ): string {
        // Sanity-check the desired output length.
        if ($length < 0 || $length > (255 * \SODIUM_CRYPTO_GENERICHASH_KEYBYTES)) {
            throw new InvalidDigestLength(
                'Argument 2: Bad HKDF Digest Length'
            );
        }
        // "If [salt] not provided, is set to a string of HashLen zeroes."
        if (empty($salt)) {
            // @codeCoverageIgnoreStart
            $salt = \str_repeat("\x00", \SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
            // @codeCoverageIgnoreEnd
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = self::raw_keyed_hash($ikm, $salt);

        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        // @codeCoverageIgnoreStart
        if (Binary::safeStrlen($prk) < \SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
            throw new CannotPerformOperation(
                'An unknown error has occurred'
            );
        }
        // @codeCoverageIgnoreEnd
        // T(0) = ''
        $t = '';
        $last_block = '';
        for ($block_index = 1; Binary::safeStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = self::raw_keyed_hash(
                $last_block . $info . \chr($block_index),
                $prk
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }
        // ORM = first L octets of T
        /** @var string $orm */
        $orm = Binary::safeSubstr($t, 0, $length);
        return $orm;
    }

    /**
     * Convert an array of integers to a string
     *
     * @param array<int, int> $integers
     * @return string
     */
    public static function intArrayToString(array $integers): string
    {
        $args = $integers;
        foreach ($args as $i => $v) {
            $args[$i] = (int) ($v & 0xff);
        }
        return \pack(
            \str_repeat('C', \count($args)),
            ...$args
        );
    }

    /**
     * Convert an integer to a string (without cache-timing side-channels)
     *
     * @param int $int
     * @return string
     */
    public static function intToChr(int $int): string
    {
        return \pack('C', $int);
    }

    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Expects a key (binary string).
     * Returns hexadecimal characters.
     *
     * @param string $input
     * @param string $key
     * @param int $length
     * @return string
     * @throws CannotPerformOperation
     * @throws \TypeError
     * @throws \SodiumException
     */
    public static function keyed_hash(
        string $input,
        string $key,
        int $length = \SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        return Hex::encode(
            self::raw_keyed_hash($input, $key, $length)
        );
    }

    /**
     * Wrapper around SODIUM_CRypto_generichash()
     *
     * Expects a key (binary string).
     * Returns raw binary.
     *
     * @param string $input
     * @param string $key
     * @param int $length
     * @return string
     * @throws CannotPerformOperation
     * @throws \SodiumException
     */
    public static function raw_keyed_hash(
        string $input,
        string $key,
        int $length = \SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        if ($length < \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new CannotPerformOperation(
                \sprintf(
                    'Output length must be at least %d bytes.',
                    \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN
                )
            );
        }
        if ($length > \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new CannotPerformOperation(
                \sprintf(
                    'Output length must be at most %d bytes.',
                    \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
                )
            );
        }
        return \sodium_crypto_generichash($input, $key, $length);
    }

    /**
     * PHP 7 uses interned strings. We don't want altering this one to alter
     * the original string.
     *
     * @param string $string
     * @return string
     * @throws \TypeError
     */
    public static function safeStrcpy(string $string): string
    {
        $length = Binary::safeStrlen($string);
        $return = '';
        /** @var int $chunk */
        $chunk = $length >> 1;
        if ($chunk < 1) {
            $chunk = 1;
        }
        for ($i = 0; $i < $length; $i += $chunk) {
            $return .= Binary::safeSubstr($string, $i, $chunk);
        }
        return $return;
    }

    /**
     * Turn a string into an array of integers
     *
     * @param string $string
     * @return array<int, int>
     * @throws \TypeError
     */
    public static function stringToIntArray(string $string): array
    {
        /**
         * @var array<int, int>
         */
        $values = \array_values(\unpack('C*', $string));
        return $values;
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
        $length = Binary::safeStrlen($left);
        if ($length !== Binary::safeStrlen($right)) {
            throw new InvalidType(
                'Both strings must be the same length'
            );
        }
        if ($length < 1) {
            return '';
        }
        return (string) ($left ^ $right);
    }
}
