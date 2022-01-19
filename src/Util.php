<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

use Error;
use ParagonIE\ConstantTime\{
    Binary,
    Hex
};
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength,
    InvalidType
};
use ParagonIE\Halite\Symmetric\EncryptionKey;
use RangeException;
use SodiumException;
use Throwable;
use TypeError;
use const
    SODIUM_CRYPTO_GENERICHASH_BYTES,
    SODIUM_CRYPTO_GENERICHASH_BYTES_MIN,
    SODIUM_CRYPTO_GENERICHASH_BYTES_MAX,
    SODIUM_CRYPTO_GENERICHASH_KEYBYTES;
use function
    array_values,
    count,
    implode,
    pack,
    sodium_crypto_generichash,
    sodium_memzero,
    sprintf,
    str_repeat,
    unpack;

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
     * @throws Error
     * @codeCoverageIgnore
     */
    final private function __construct()
    {
        throw new Error('Do not instantiate');
    }

    /**
     * Convert a character to an integer (without cache-timing side-channels)
     *
     * @param string $chr
     *
     * @return int
     *
     * @throws RangeException
     */
    public static function chrToInt(string $chr): int
    {
        if (Binary::safeStrlen($chr) !== 1) {
            throw new RangeException('Must be a string with a length of 1');
        }
        $result = unpack('C', $chr);
        return (int) $result[1];
    }

    /**
     * Wrapper around sodium_crypto_generichash()
     *
     * Returns hexadecimal characters.
     *
     * @param string $input
     * @param int $length
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     * @throws TypeError
     */
    public static function hash(
        string $input,
        int $length = SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        return Hex::encode(
            self::raw_keyed_hash($input, '', $length)
        );
    }

    /**
     * Wrapper around sodium_crypto_generichash()
     *
     * Returns raw binary.
     *
     * @param string $input
     * @param int $length
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     */
    public static function raw_hash(
        string $input,
        int $length = SODIUM_CRYPTO_GENERICHASH_BYTES
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
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws TypeError
     * @throws SodiumException
     */
    public static function hkdfBlake2b(
        string $ikm,
        int $length,
        string $info = '',
        string $salt = ''
    ): string {
        // Sanity-check the desired output length.
        if ($length < 0 || $length > (255 * SODIUM_CRYPTO_GENERICHASH_KEYBYTES)) {
            throw new InvalidDigestLength(
                'Argument 2: Bad HKDF Digest Length'
            );
        }
        // "If [salt] not provided, is set to a string of HashLen zeroes."
        if (empty($salt)) {
            // @codeCoverageIgnoreStart
            $salt = str_repeat("\x00", SODIUM_CRYPTO_GENERICHASH_KEYBYTES);
            // @codeCoverageIgnoreEnd
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        //
        // Note: The notation used by the RFC is backwards from what we're doing here.
        // They use (Key, Msg) while our API is (Msg, Key).
        $prk = self::raw_keyed_hash($ikm, $salt);

        // HKDF-Expand:
        // This check is useless, but it serves as a reminder to the spec.
        // @codeCoverageIgnoreStart
        if (Binary::safeStrlen($prk) < SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
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
                $last_block . $info . pack('C', $block_index),
                $prk
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }
        // ORM = first L octets of T
        return Binary::safeSubstr($t, 0, $length);
    }

    /**
     * Convert an array of integers to a string
     *
     * @param array<int, int> $integers
     *
     * @return string
     */
    public static function intArrayToString(array $integers): string
    {
        $args = $integers;
        foreach ($args as $i => $v) {
            $args[$i] = (int) ($v & 0xff);
        }
        return pack(
            str_repeat('C', count($args)),
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
        return pack('C', $int);
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
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws SodiumException
     */
    public static function keyed_hash(
        string $input,
        string $key,
        int $length = SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        return Hex::encode(
            self::raw_keyed_hash($input, $key, $length)
        );
    }

    /**
     * Pre-authentication encoding
     *
     * @param string ...$pieces
     *
     * @return string
     */
    public static function PAE(string ...$pieces): string
    {
        $out = [];
        $out[] = pack('P', count($pieces));
        foreach ($pieces as $piece) {
            $out[] = pack('P', Binary::safeStrlen($piece)) . $piece;
        }
        return implode($out);
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
     *
     * @return string
     *
     * @throws CannotPerformOperation
     * @throws SodiumException
     */
    public static function raw_keyed_hash(
        string $input,
        string $key,
        int $length = SODIUM_CRYPTO_GENERICHASH_BYTES
    ): string {
        if ($length < SODIUM_CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new CannotPerformOperation(
                sprintf(
                    'Output length must be at least %d bytes.',
                    SODIUM_CRYPTO_GENERICHASH_BYTES_MIN
                )
            );
        }
        if ($length > SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new CannotPerformOperation(
                sprintf(
                    'Output length must be at most %d bytes.',
                    SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
                )
            );
        }
        return sodium_crypto_generichash($input, $key, $length);
    }

    /**
     * PHP 7 uses interned strings. We don't want altering this one to alter
     * the original string.
     *
     * @param string $string
     *
     * @return string
     *
     * @throws TypeError
     */
    public static function safeStrcpy(string $string): string
    {
        $length = Binary::safeStrlen($string);
        $return = '';
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
     * Split a key (using HKDF-BLAKE2b instead of HKDF-HMAC-*)
     *
     * @param EncryptionKey $master
     * @param string $salt
     * @param Config $config
     *
     * @return string[]
     *
     * @throws CannotPerformOperation
     * @throws InvalidDigestLength
     * @throws SodiumException
     * @throws TypeError
     */
    public static function splitKeys(
        EncryptionKey $master,
        string $salt,
        Config $config
    ): array {
        $binary = $master->getRawKeyMaterial();

        /*
         * From Halite version 5, we use the HKDF info parameter instead of the salt.
         * This does two things:
         *
         * 1. It allows us to use the HKDF security definition (which is stronger than a PRF)
         * 2. It allows us to reuse the intermediary step and make key derivation faster.
         */
        if ($config->HKDF_USE_INFO) {
            $prk = self::raw_keyed_hash(
                $binary,
                str_repeat("\x00", SODIUM_CRYPTO_GENERICHASH_KEYBYTES)
            );
            $return = [
                self::raw_keyed_hash(((string) $config->HKDF_SBOX) . $salt . "\x01", $prk),
                self::raw_keyed_hash(((string) $config->HKDF_AUTH) . $salt . "\x01", $prk)
            ];
            self::memzero($prk);
            return $return;
        }

        /*
         * Halite 4 and blow used this strategy:
         */
        return [
            Util::hkdfBlake2b(
                $binary,
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                (string) $config->HKDF_SBOX,
                $salt
            ),
            Util::hkdfBlake2b(
                $binary,
                SODIUM_CRYPTO_AUTH_KEYBYTES,
                (string) $config->HKDF_AUTH,
                $salt
            )
        ];
    }

    /**
     * Turn a string into an array of integers
     *
     * @param string $string
     *
     * @return array<int, int>
     *
     * @throws TypeError
     */
    public static function stringToIntArray(string $string): array
    {
        /**
         * @var array<int, int>
         */
        $values = array_values(unpack('C*', $string));
        return $values;
    }

    /**
     * Calculate A xor B, given two binary strings of the same length.
     *
     * @param string $left
     * @param string $right
     *
     * @return string
     *
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

    /**
     * Wrap memzero() without breaking on sodium_compat
     *
     * @param string &$var
     *
     * @return void
     *
     * @psalm-param-out null $var
     * @psalm-suppress UnnecessaryVarAnnotation
     * @psalm-suppress InvalidOperand
     */
    public static function memzero(string &$var): void
    {
        try {
            sodium_memzero($var);
        } catch (Throwable $ex) {
            // Best-effort:
            $var ^= $var;
        }
        unset($var);
    }
}
