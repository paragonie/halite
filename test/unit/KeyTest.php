<?php
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use \ParagonIE\Halite\Symmetric\AuthenticationKey;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class KeyTest extends PHPUnit_Framework_TestCase
{
    public function testDerive()
    {
        $key = KeyFactory::deriveEncryptionKey(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $this->assertEquals(
            $key->get(),
            "\x36\xa6\xc2\xb9\x6a\x65\x0d\x80\xbf\x7e\x02\x5e\x0f\x58\xf3\xd6".
            "\x36\x33\x95\x75\xde\xfb\x37\x08\x01\xa5\x42\x13\xbd\x54\x58\x2d"
        );
        $salt = \Sodium\hex2bin(
            '762ce4cabd543065172236de1027536ad52ec4c9133ced3766ff319f10301888'
        );
        
        // Issue #10
        $enc_secret = KeyFactory::deriveEncryptionKey(
            'correct horse battery staple',
            $salt,
            Key::ENCRYPTION | Key::SECRET_KEY
        );
        $this->assertTrue(
            $enc_secret->isEncryptionKey()
        );
    }
    
    public function testDeriveSigningKey()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $sign_secret = $keypair->getSecretKey();
        $sign_public = $keypair->getPublicKey();
        
        $this->assertTrue($sign_secret instanceof SignatureSecretKey);
        $this->assertTrue($sign_public instanceof SignaturePublicKey);
        
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
    
    public function testKeyTypes()
    {
        $key = KeyFactory::generateAuthenticationKey();
            $this->assertFalse($key->isAsymmetricKey());
            $this->assertFalse($key->isEncryptionKey());
            $this->assertTrue($key->isSecretKey());
            $this->assertTrue($key->isSigningKey());
            $this->assertFalse($key->isPublicKey());
        
        $key = KeyFactory::generateEncryptionKey();
            $this->assertFalse($key->isAsymmetricKey());
            $this->assertTrue($key->isEncryptionKey());
            $this->assertTrue($key->isSecretKey());
            $this->assertFalse($key->isSigningKey());
            $this->assertFalse($key->isPublicKey());
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $enc_secret = $keypair->getSecretKey();
            $enc_public = $keypair->getPublicKey();
            $this->assertTrue($enc_secret->isAsymmetricKey());
            $this->assertTrue($enc_secret->isEncryptionKey());
            $this->assertTrue($enc_secret->isSecretKey());
            $this->assertFalse($enc_secret->isSigningKey());
            $this->assertFalse($enc_secret->isPublicKey());
            
            $this->assertTrue($enc_public->isAsymmetricKey());
            $this->assertTrue($enc_public->isEncryptionKey());
            $this->assertFalse($enc_public->isSecretKey());
            $this->assertFalse($enc_public->isSigningKey());
            $this->assertTrue($enc_public->isPublicKey());
            
        $keypair = KeyFactory::generateSignatureKeyPair();
            $sign_secret = $keypair->getSecretKey();
            $sign_public = $keypair->getPublicKey();
            $this->assertTrue($sign_secret->isAsymmetricKey());
            $this->assertFalse($sign_secret->isEncryptionKey());
            $this->assertTrue($sign_secret->isSecretKey());
            $this->assertTrue($sign_public->isSigningKey());
            $this->assertFalse($sign_secret->isPublicKey());
            
            $this->assertTrue($sign_public->isAsymmetricKey());
            $this->assertFalse($sign_public->isEncryptionKey());
            $this->assertFalse($sign_public->isSecretKey());
            $this->assertTrue($sign_public->isSigningKey());
            $this->assertTrue($sign_public->isPublicKey());
    }
    
    public function testEncKeyStorage()
    {
        $enc_keypair = KeyFactory::deriveEncryptionKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $enc_secret = $enc_keypair->getSecretKey();
        $enc_public = $enc_keypair->getPublicKey();
        
        $file_secret = \tempnam(__DIR__.'/tmp', 'key');
        $file_public = \tempnam(__DIR__.'/tmp', 'key');
        
        $this->assertTrue(
            KeyFactory::save($enc_secret, $file_secret) !== false
        );
        $this->assertTrue(
            KeyFactory::save($enc_public, $file_public) !== false
        );
        
        $load_public = KeyFactory::loadEncryptionPublicKey($file_public);
        $this->assertTrue(
            $load_public instanceof EncryptionPublicKey
        );
        $this->assertTrue(
            \hash_equals($enc_public->get(), $load_public->get())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }
    
    public function testSignKeyStorage()
    {
        $sign_keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        );
        $sign_secret = $sign_keypair->getSecretKey();
        $sign_public = $sign_keypair->getPublicKey();
        
        $file_secret = \tempnam(__DIR__.'/tmp', 'key');
        $file_public = \tempnam(__DIR__.'/tmp', 'key');
        
        $this->assertTrue(
            KeyFactory::save($sign_secret, $file_secret) !== false
        );
        $this->assertTrue(
            KeyFactory::save($sign_public, $file_public) !== false
        );
        
        $load_public = KeyFactory::loadSignaturePublicKey($file_public);
        $this->assertTrue(
            $load_public instanceof SignaturePublicKey
        );
        $this->assertTrue(
            \hash_equals($sign_public->get(), $load_public->get())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }
}
