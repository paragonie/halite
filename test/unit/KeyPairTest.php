<?php
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Asymmetric\SecretKey as ASecretKey;
use \ParagonIE\Halite\Asymmetric\PublicKey as APublicKey;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class KeyPairTest extends PHPUnit_Framework_TestCase
{
    public function testDeriveSigningKey()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $sign_secret = $keypair->getSecretKey();
        $sign_public = $keypair->getPublicKey();
        
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
    
    public function testFileStorage()
    {
        $filename = \tempnam(__DIR__.'/tmp/', 'key');
        $key = KeyFactory::generateEncryptionKeyPair();
        KeyFactory::save($key, $filename);
        
        $copy = KeyFactory::loadEncryptionKeyPair($filename);
        
        $this->assertEquals(
            $key->getPublicKey()->get(),
            $copy->getPublicKey()->get()
        );
        \unlink($filename);
    }
    
    /**
     * @covers \ParagonIE\Halite\Asymmetric\EncryptionSecretKey::derivePublicKey()
     * @covers \ParagonIE\Halite\Asymmetric\SignatureSecretKey::derivePublicKey()
     */
    public function testPublicDerivation()
    {
        $enc_kp = KeyFactory::generateEncryptionKeyPair();
        $enc_secret = $enc_kp->getSecretKey();
        $enc_public = $enc_kp->getPublicKey();
        
        $this->assertEquals(
            $enc_secret->derivePublicKey()->get(),
            $enc_public->get()
        );
        
        $sign_kp = KeyFactory::generateSignatureKeyPair();
        $sign_secret = $sign_kp->getSecretKey();
        $sign_public = $sign_kp->getPublicKey();
        $this->assertEquals(
            $sign_secret->derivePublicKey()->get(),
            $sign_public->get()
        );
    }
}
