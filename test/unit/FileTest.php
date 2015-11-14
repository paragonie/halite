<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Util;
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\EncryptionKeyPair;
use \ParagonIE\Halite\SignatureKeyPair;
use \ParagonIE\Halite\Symmetric\EncryptionKey;
use \ParagonIE\Halite\Alerts as CryptoException;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class FileTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.encrypted.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.decrypted.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.decrypted.png', 0777);
        
        $key = new EncryptionKey(\str_repeat('B', 32));
        File::encryptFile(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            $key
        );
        
        File::decryptFile(
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            __DIR__.'/tmp/paragon_avatar.decrypted.png',
            $key
        );
        
        $this->assertEquals(
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.decrypted.png')
        );
        \unlink(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        \unlink(__DIR__.'/tmp/paragon_avatar.decrypted.png');
    }
    
    public function testEncryptFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png', 0777);
        
        $key = new EncryptionKey(\str_repeat('B', 32));
        File::encryptFile(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypt_fail.png',
            $key
        );
        
        $fp = \fopen(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 'ab');
        \fwrite($fp, \Sodium\randombytes_buf(1));
        fclose($fp);
            
        try {
            File::decryptFile(
                __DIR__.'/tmp/paragon_avatar.encrypt_fail.png',
                __DIR__.'/tmp/paragon_avatar.decrypt_fail.png',
                $key
            );
            $this->fail(
                'This should have thrown an InvalidMessage exception!'
            );
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
            \unlink(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
            \unlink(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        }
    }
    
    public function testSeal()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        File::sealFile(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            $publickey
        );
        
        File::unsealFile(
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            __DIR__.'/tmp/paragon_avatar.opened.png',
            $secretkey
        );
        
        $this->assertEquals(
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );
        
        \unlink(__DIR__.'/tmp/paragon_avatar.sealed.png');
        \unlink(__DIR__.'/tmp/paragon_avatar.opened.png');
    }
    
    public function testSealFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.open_fail.png', 0777);
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        File::sealFile(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.seal_fail.png',
            $publickey
        );
        
        $fp = \fopen(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 'ab');
        \fwrite($fp, \Sodium\randombytes_buf(1));
        fclose($fp);
        
        try {
            File::unsealFile(
                __DIR__.'/tmp/paragon_avatar.seal_fail.png',
                __DIR__.'/tmp/paragon_avatar.open_fail.png',
                $secretkey
            );
            $this->fail(
                'This should have thrown an InvalidMessage exception!'
            );
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
            \unlink(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
            \unlink(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        }
    }
    
    public function testSign()
    {
        $keypair = KeyFactory::generateSignatureKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        $signature = File::signFile(
            __DIR__.'/tmp/paragon_avatar.png',
            $secretkey
        );
        
        $this->assertTrue(
            File::verifyFile(
                __DIR__.'/tmp/paragon_avatar.png',
                $publickey,
                $signature
            )
        );
    }
    
    public function testChecksum()
    {
        $csum = File::checksumFile(__DIR__.'/tmp/paragon_avatar.png');
        $this->assertEquals(
            $csum,
            "09f9f74a0e742d057ca08394db4c2e444be88c0c94fe9a914c3d3758c7eccafb".
            "8dd286e3d6bc37f353e76c0c5aa2036d978ca28ffaccfa59f5dc1f076c5517a0"
        );
        
        $data = \Sodium\randombytes_buf(32);
        \file_put_contents(__DIR__.'/tmp/garbage.dat', $data);
        
        $hash = \Sodium\crypto_generichash($data, null, 64);
        $file = File::checksumFile(__DIR__.'/tmp/garbage.dat', null, true);
        $this->assertEquals(
            $hash,
            $file
        );
        \unlink(__DIR__.'/tmp/garbage.dat');
    }
}
