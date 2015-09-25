<?php
use \ParagonIE\Halite\Key;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class KeyTest extends PHPUnit_Framework_TestCase
{
    public function testDerive()
    {
        $key = Key::deriveFromPassword(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $this->assertEquals(
            $key->get(),
            "\x36\xa6\xc2\xb9\x6a\x65\x0d\x80\xbf\x7e\x02\x5e\x0f\x58\xf3\xd6".
            "\x36\x33\x95\x75\xde\xfb\x37\x08\x01\xa5\x42\x13\xbd\x54\x58\x2d"
        );
    }
    
    
}
