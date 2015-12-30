<?php
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Util;

/**
 * Halite Util test case
 *
 * @category   HaliteTest
 * @package    Halite
 * @author     Stefanie Schmidt <stefanie@reneschmidt.de>
 * @license    http://opensource.org/licenses/GPL-3.0 GPL 3
 * @link       https://paragonie.com/project/halite
 */
class UtilTest extends PHPUnit_Framework_TestCase
{
    /**
     * Test our HKDF-esque construct built atop BLAKE2b
     * 
     * @covers Util::hkdfBlake2b()
     */
    public function testBlake2bKDF()
    {
        $ikm = 'YELLOW SUBMARINE';
        $len = 32;
        $info = 'TESTING HKDF-BLAKE2B';
        $salt = str_repeat("\x80", 32);
        
        $test = Util::hkdfBlake2b($ikm, $len, $info, $salt);
        $this->assertEquals(
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
    }
    
    /**
     * @covers Util::safeStrlen()
     */
    public function testSafeStrlen()
    {
        $valid = "\xF0\x9D\x92\xB3"; // One 4-byte UTF-8 character
        $this->assertEquals(Util::safeStrlen($valid), 4);
    }
    
    /**
     * test safeStrlen() with illegal parameter. We expect to see an exception
     * @return void
     * @throws CannotPerformOperation
     * 
     * @covers Util::safeStrlen()
     */
    public function testSafeStrlenFail()
    {
        $this->setExpectedException('\ParagonIE\Halite\Alerts\HaliteAlert');

        $teststring = []; // is not a string, will provoke a warning

        Util::safeStrlen($teststring);
    }
    
    /**
     * Verify that safeSubstr() operates over binary data.
     * 
     * @covers Util::safeSubstr()
     */
    public function testSafeSubstr()
    {
        $string = \str_repeat("\xF0\x9D\x92\xB3", 4);
        $this->assertEquals(Util::safeSubstr($string, 0, 1), "\xF0");
        $this->assertEquals(Util::safeSubstr($string, 1, 1), "\x9D");
        $this->assertEquals(Util::safeSubstr($string, 2, 1), "\x92");
        $this->assertEquals(Util::safeSubstr($string, 3, 1), "\xB3");
        $this->assertEquals(Util::safeSubstr($string, 0, 2), "\xF0\x9D");
        $this->assertEquals(Util::safeSubstr($string, 2, 2), "\x92\xB3");
    }
}
