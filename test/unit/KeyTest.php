<?php
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Asymmetric\SecretKey as ASecretKey;
use \ParagonIE\Halite\Asymmetric\PublicKey as APublicKey;
use \ParagonIE\Halite\Symmetric\SecretKey as SecretKey;

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
    
    public function testDeriveSigningKey()
    {
        list($sign_secret, $sign_public) = ASecretKey::deriveFromPassword(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            Key::CRYPTO_SIGN
        );
        
        $this->assertTrue($sign_secret instanceof ASecretKey);
        $this->assertTrue($sign_public instanceof APublicKey);
        
        // Can this be used?        
        $message = 'This is a test message';
        $signed = Asymmetric::sign(
            $message,
            $sign_secret
        );
        $this->assertTrue(
            Asymmetric::verify($message, $sign_public, $signed)
        );
        
        $this->assertEquals(
            $sign_public->get(),
            "\xfe\x1b\x09\x86\x45\xb7\x04\xf5\xc2\x7f\x62\xc8\x61\x67\xd6\x09".
            "\x03\x1d\x95\xa7\x94\x5c\xe6\xd5\x55\x96\xe3\x75\x03\x17\x88\x34"
        );
    }
}
