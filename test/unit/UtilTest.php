<?php
declare(strict_types=1);

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidDigestLength;
use ParagonIE\Halite\Util;
use ParagonIE\Halite\Alerts\InvalidType;
use PHPUnit\Framework\TestCase;

/**
 * Halite Util test case
 *
 * @category   HaliteTest
 * @package    Halite
 * @author     Stefanie Schmidt <stefanie@reneschmidt.de>
 * @license    http://opensource.org/licenses/GPL-3.0 GPL 3
 * @link       https://paragonie.com/project/halite
 */
final class UtilTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testChrToInt()
    {
        $this->assertSame(0x61, Util::chrToInt("a"));
        $this->assertSame(0xe0, Util::chrToInt("\xe0"));
        try {
            Util::chrToInt("ab");
        } catch (\RangeException $ex) {
        }
        $random = random_int(0, 255);
        $this->assertSame(
            $random,
            Util::chrToInt(Util::intToChr($random))
        );
    }

    public function testIntArrayToString()
    {
        $this->assertSame("\x00\x01\x03\x04", Util::intArrayToString([0,1,3,4]), 'Unexpected result');
        $this->assertSame("\x00\x01\x03\x04", Util::intArrayToString([256,257,259,260]), 'Masking failed');
    }

    /**
     * @throws TypeError
     */
    public function testStringToIntArray()
    {
        $this->assertSame([0,1,3,4], Util::stringToIntArray("\x00\x01\x03\x04"), 'Unexpected result');
    }

    /**
     * BLAKE2b hash
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     */
    public function testHash()
    {
        $this->assertSame(
            Util::raw_hash(''),
            "\x0e\x57\x51\xc0\x26\xe5\x43\xb2\xe8\xab\x2e\xb0\x60\x99\xda\xa1".
            "\xd1\xe5\xdf\x47\x77\x8f\x77\x87\xfa\xab\x45\xcd\xf1\x2f\xe3\xa8"
        );

        $this->assertSame(
            Util::hash('Large Hashron Collider'),
            '6c9a1f2b06d1f13ae845873ad470ea5eb78866c60b3f1f46733e89aee898fa46'
        );
    }

    /**
     * BLAKE2b hash
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     */
    public function testKeyedHash()
    {
        $key = Util::raw_hash('');
        $this->assertSame(
            Util::raw_keyed_hash('', $key),
            "\x0a\x28\xe9\x66\xfb\x7a\x7d\x39\xfd\x0a\x4d\x12\xd6\xfb\x14\x62".
            "\x5b\x94\xb1\x73\x89\x43\x33\x8d\x2b\x3d\xf4\xcc\x81\xcb\x4e\xf0"
        );

        $this->assertSame(
            Util::keyed_hash('Large Hashron Collider', $key),
            '4cca9839943964a68a64535ea22f1cc796df6da130619a69d1022b84ef881881'
        );

        try {
            Util::keyed_hash('Large Hashron Collider', $key, 15);
            $this->fail('Invalid size accepted (15)');
        } catch (CannotPerformOperation $ex) {
            $this->assertSame(
                'Output length must be at least 16 bytes.',
                $ex->getMessage()
            );
        }

        try {
            Util::keyed_hash('Large Hashron Collider', $key, 65);
            $this->fail('Invalid size accepted (65)');
        } catch (CannotPerformOperation $ex) {
            $this->assertSame(
                'Output length must be at most 64 bytes.',
                $ex->getMessage()
            );
        }
    }

    /**
     * Test our HKDF-esque construct built atop BLAKE2b
     *
     * @throws CannotPerformOperation
     * @throws TypeError
     * @throws InvalidDigestLength
     */
    public function testBlake2bKDF()
    {
        $ikm = 'YELLOW SUBMARINE';
        $len = 32;
        $info = 'TESTING HKDF-BLAKE2B';
        $salt = str_repeat("\x80", 32);
        
        $test = Util::hkdfBlake2b($ikm, $len, $info, $salt);
        $this->assertSame(
            $test,
            "\x7b\xaf\xb1\x11\x1c\xda\xce\x81\xd1\xb0\x73\xff\x6e\x68\x8f\xc3".
            "\x6f\xb5\xa2\xc7\xbd\x53\xf6\xf1\xb4\x2f\x80\x71\x29\x4b\xb7\xf7"
        );
        // Let's change the IKM
        $ikmB = 'YELLOW SUBMARINF';
        $testIkm = Util::hkdfBlake2b($ikmB, $len, $info, $salt);
        $this->assertNotEquals($test, $testIkm);
        
        // Let's change the info
        $infoB = 'TESTING HKDF-BLAKE2C';
        $testInfo = Util::hkdfBlake2b($ikm, $len, $infoB, $salt);
        $this->assertNotEquals($test, $testInfo);
        
        // Let's change the salt
        $saltB = str_repeat("\x80", 31) . "\x81";
        $testSalt = Util::hkdfBlake2b($ikm, $len, $info, $saltB);
        $this->assertNotEquals($test, $testSalt);

        try {
            Util::hkdfBlake2b($ikm, -1, $info, $saltB);
            $this->fail('Invalid digest length was accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidDigestLength $ex) {
        }
    }

    /**
     * Verify that safeStrcpy() doesn't fall prey to interned strings.
     *
     * @throws Exception
     * @throws TypeError
     */
    public function testSafeStrcpy()
    {
        $unique = random_bytes(128);
        $clone = Util::safeStrcpy($unique);
        $this->assertSame($unique, $clone);
        sodium_memzero($unique);
        $this->assertNotSame($unique, $clone);

        // See issue #97
        $unique = random_bytes(1);
        $clone = Util::safeStrcpy($unique);
        $this->assertSame($unique, $clone);
        sodium_memzero($unique);
        $this->assertNotSame($unique, $clone);
    }

    /**
     * Verify that xorStrings() produces the expected result.
     *
     * @throws InvalidType
     */
    public function testXorStrings()
    {
        $this->assertSame('', Util::xorStrings('', ''));
        $a = str_repeat("\x0f", 32);
        $b = str_repeat("\x88", 32);
        $this->assertSame(
            str_repeat("\x87", 32),
            Util::xorStrings($a, $b)
        );

        try {
            $a .= "\x00";
            $this->assertSame(
                str_repeat("\x87", 32),
                Util::xorStrings($a, $b)
            );
            $this->fail('Incorrect string length should throw an exception.');
        } catch (InvalidType $ex) {
        }
    }
}
