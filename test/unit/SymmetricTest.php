<?php
use \ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use \ParagonIE\Halite\Alerts as CryptoException;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class SymmetricTest extends PHPUnit_Framework_TestCase
{
    public function testAuthenticate()
    {
        $key = new \ParagonIE\Halite\Key(
            \str_repeat('A', 32),
            false,
            true,
            false
        );
        $message = 'test message';
        $mac = Symmetric::authenticate($message, $key);
        $this->assertTrue(
            Symmetric::verify($message, $key, $mac)
        );
    }
    
    public function testAuthenticateFail()
    {
        $key = new \ParagonIE\Halite\Key(
            \str_repeat('A', 32),
            false,
            true,
            false
        );
        $message = 'test message';
        $mac = Symmetric::authenticate($message, $key, true);
        
        // Test invalid message
        $this->assertFalse(
            Symmetric::verify('othermessage', $key, $mac, true)
        );
        
        $r = \Sodium\randombytes_uniform(\mb_strlen($mac, '8bit'));
        
        $_mac = $mac;
        $_mac[$r] = \chr(
            \ord($_mac[$r])
                ^
            1 << \Sodium\randombytes_uniform(8)
        );
        
        // Test invalid signature
        $this->assertFalse(
            Symmetric::verify($message, $key, $_mac, true)
        );
    }
    
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
    
    public function testEncryptFail()
    {
        $key = new \ParagonIE\Halite\Key(
            \str_repeat('A', 32)
        );
        $message = Symmetric::encrypt('test message', $key, true);
        $r = \Sodium\randombytes_uniform(\mb_strlen($message, '8bit'));
        $message[$r] = \chr(
            \ord($message[$r])
                ^
            1 << \Sodium\randombytes_uniform(8)
        );
        try {
            $plain = Symmetric::decrypt($message, $key, true);
            $this->assertEquals($plain, $message);
            throw new Exception('ERROR: THIS SHOULD ALWAYS FAIL');
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
}