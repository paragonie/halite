<?php
use \ParagonIE\Halite\Alerts\InvalidType;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use \ParagonIE\Halite\Asymmetric\SignatureSecretKey;

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
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        );
        $this->assertSame(
            $key->getRawKeyMaterial(),
            "\x79\x12\x36\xc1\xf0\x6b\x73\xbd\xaa\x88\x89\x80\xe3\x2c\x4b\xdb".
            "\x25\xd1\xf9\x39\xe5\xf7\x13\x30\x5c\xd8\x4c\x50\x22\xcc\x96\x6e"
        );
        $salt = \Sodium\hex2bin(
            '762ce4cabd543065172236de1027536a'
        );
        
        // Issue #10
        $enc_secret = KeyFactory::deriveEncryptionKey(
            'correct horse battery staple',
            $salt,
            false
        );
        $this->assertTrue(
            $enc_secret->isEncryptionKey()
        );
    }
    
    public function testLegacyDerive()
    {
        $key = KeyFactory::deriveEncryptionKey(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            true
        );
        $this->assertSame(
            $key->getRawKeyMaterial(),
            "\x36\xa6\xc2\xb9\x6a\x65\x0d\x80\xbf\x7e\x02\x5e\x0f\x58\xf3\xd6".
            "\x36\x33\x95\x75\xde\xfb\x37\x08\x01\xa5\x42\x13\xbd\x54\x58\x2d",
            true
        );
        $salt = \Sodium\hex2bin(
            '762ce4cabd543065172236de1027536ad52ec4c9133ced3766ff319f10301888'
        );
        
        // Issue #10
        $enc_secret = KeyFactory::deriveEncryptionKey(
            'correct horse battery staple',
            $salt,
            true
        );
        $this->assertTrue(
            $enc_secret->isEncryptionKey()
        );
    }
    
    public function testDeriveSigningKey()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
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
        
        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
            "\x88\x9c\xc0\x7a\x90\xb8\x98\xf4\x6b\x47\xfe\xcc\x91\x42\x58\x45".
            "\x41\xcf\x4b\x5c\x6a\x82\x2d\xdc\xc6\x8b\x87\xbc\x08\x2f\xfe\x95"
        );
    }
    
    public function testLegacyDeriveSigningKey()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            true
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
        
        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
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
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
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
            \hash_equals($enc_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }
    
    public function testLegacyEncKeyStorage()
    {
        $enc_keypair = KeyFactory::deriveEncryptionKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            true
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
            \hash_equals($enc_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }
    
    public function testSignKeyStorage()
    {
        $sign_keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
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
            \hash_equals($sign_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }
    
    public function testLegacySignKeyStorage()
    {
        $sign_keypair = KeyFactory::deriveSignatureKeyPair(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            true
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
            \hash_equals($sign_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }

    public function testInvalidKeyLevels()
    {
        /*
        return $this->markTestSkipped('This is a very slow test. Feel free to enable it to verify correctness.');
        */
        try {
            KeyFactory::deriveEncryptionKey(
                'apple',
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" .
                "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
                true,
                KeyFactory::MODERATE
            );
            $this->fail('Scrypt should fail on MODERATE');
        } catch (InvalidType $ex) {
            $this->assertSame(
                'Invalid security level for scrypt',
                $ex->getMessage()
            );
        }
        try {
            KeyFactory::deriveEncryptionKey(
                'apple',
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                false,
                'INVALID SECURITY LEVEL IDENTIFIER SHOULD HAVE USED A CONSTANT INSTEAD'
            );
            $this->fail('Argon2 should fail on invalid');
        } catch (InvalidType $ex) {
            $this->assertSame(
                'Invalid security level for Argon2i',
                $ex->getMessage()
            );
        }
    }

    public function testKeyLevels()
    {
        return $this->markTestSkipped('This is a very slow test. Feel free to enable it to verify correctness.');

        $key = KeyFactory::deriveEncryptionKey(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            true,
            KeyFactory::SENSITIVE
        );
        $this->assertSame(
            \Sodium\bin2hex($key->getRawKeyMaterial()),
            'c6e0821d9df7a5f796ee712109b948772331a9ef6cedb45dcd0abf258ee6822e'
        );

        $key = KeyFactory::deriveEncryptionKey(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            false,
            KeyFactory::MODERATE
        );
        $this->assertSame(
            \Sodium\bin2hex($key->getRawKeyMaterial()),
            '227817a188e55a679ddc8b1ca51f7aba4d1086f0512f9e3eb547c2392d49bde9'
        );

        $key = KeyFactory::deriveEncryptionKey(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            false,
            KeyFactory::SENSITIVE
        );
        $this->assertSame(
            \Sodium\bin2hex($key->getRawKeyMaterial()),
            'c5e8ac6e81ffd5c4f9f985e5c49e2b66d760167e739f424b346b1d747e711446'
        );
    }
}
