<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;
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
        
        $key = new Key(\str_repeat('B', 32));
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
    }
    
    public function testEncryptFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png', 0777);
        
        $key = new Key(\str_repeat('B', 32));
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
            throw new \Exception('ERROR: THIS SHOULD ALWAYS FAIL');
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
    
    public function testSeal()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);
        
        list($secretkey, $publickey) = Key::generate(Key::CRYPTO_BOX);
        
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
    }
    
    public function testSealFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.open_fail.png', 0777);
        
        list($secretkey, $publickey) = Key::generate(Key::CRYPTO_BOX);
        
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
                __DIR__.'/tmp/paragon_avatar.opened.png',
                $secretkey
            );
            throw new \Exception('ERROR: THIS SHOULD ALWAYS FAIL');
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
}
