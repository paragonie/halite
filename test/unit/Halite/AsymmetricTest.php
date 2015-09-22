<?php
use \ParagonIE\Halite\Primitive\Asymmetric;
use \ParagonIE\Halite\Primitive\Key;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class AsymmetricTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $alice = Asymmetric::generateKeys();
        $bob = Asymmetric::generateKeys();
        
        $message = Asymmetric::encrypt(
            'test message',
            $alice->getSecretKey(),
            $bob->getPublicKey()
        );
        
        $this->assertTrue(strpos($message, '31420001') === 0);
        
        $plain = Asymmetric::decrypt(
            $message,
            $bob->getSecretKey(),
            $alice->getPublicKey()
        );
        
        $this->assertEquals($plain, 'test message');
    }
    
    public function testSeal()
    {
        $alice = Asymmetric::generateKeys();
        
        $message = 'This is for your eyes only';
        $sealed = Asymmetric::seal($message, $alice->getPublicKey());
        
        $opened = Asymmetric::unseal($sealed, $alice->getSecretKey());
        $this->assertTrue($opened === $message);
    }
    
    public function testSign()
    {
        $alice = Asymmetric::generateKeys(Key::CRYPTO_SIGN);
        
        $message = 'test message';
        $signature = Asymmetric::sign($message, $alice->getSecretKey());
        
        $this->assertTrue(strlen($signature) === 128);
        
        $this->assertTrue(
            Asymmetric::verify($message, $alice->getPublicKey(), $signature)
        );
    }
}
