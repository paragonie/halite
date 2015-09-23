<?php
use \ParagonIE\Halite\File;
use \ParagonIE\Halite\Key;

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
}
