<?php
use \ParagonIE\Halite\Primitive\Symmetric;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class SymmetricTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $key = new \ParagonIE\Halite\Key(
            \str_repeat('A', 32)
        );
        $message = Symmetric::encrypt('test message', $key);
        $this->assertTrue(strpos($message, '31420001') === 0);
        
        $plain = Symmetric::decrypt($message, $key);
        $this->assertEquals($plain, 'test message');
    }
    
    public function testRawEncrypt()
    {
        $key = new \ParagonIE\Halite\Key(
            \str_repeat('A', 32)
        );
        $message = Symmetric::encrypt('test message', $key, true);
        $this->assertTrue(strpos($message, \ParagonIE\Halite\Halite::HALITE_VERSION) === 0);
        
        $plain = Symmetric::decrypt($message, $key, true);
        $this->assertEquals($plain, 'test message');
    }
}