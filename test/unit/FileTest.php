<?php
declare(strict_types=1);

use ParagonIE\Halite\File;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Halite\Util;
use ParagonIE\Halite\Alerts as CryptoException;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class FileTest extends TestCase
{
    /**
     * @covers File::encrypt()
     * @covers File::decrypt()
     */
    public function testEncrypt()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.encrypted.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.decrypted.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.decrypted.png', 0777);

        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            $key
        );

        File::decrypt(
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            __DIR__.'/tmp/paragon_avatar.decrypted.png',
            $key
        );

        $this->assertSame(
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.decrypted.png')
        );
        \unlink(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        \unlink(__DIR__.'/tmp/paragon_avatar.decrypted.png');
    }

    /**
     * @covers File::encrypt()
     * @covers File::decrypt()
     */
    public function testEncryptEmpty()
    {
        \file_put_contents(__DIR__.'/tmp/empty.txt', '');
        \chmod(__DIR__.'/tmp/empty.txt', 0777);

        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/empty.txt',
            __DIR__.'/tmp/empty.encrypted.txt',
            $key
        );

        File::decrypt(
            __DIR__.'/tmp/empty.encrypted.txt',
            __DIR__.'/tmp/empty.decrypted.txt',
            $key
        );

        $this->assertSame(
            \hash_file('sha256', __DIR__.'/tmp/empty.txt'),
            \hash_file('sha256', __DIR__.'/tmp/empty.decrypted.txt')
        );
        \unlink(__DIR__.'/tmp/empty.txt');
        \unlink(__DIR__.'/tmp/empty.encrypted.txt');
        \unlink(__DIR__.'/tmp/empty.decrypted.txt');
    }

    /**
     * @covers File::encrypt()
     * @covers File::decrypt()
     */
    public function testEncryptFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png', 0777);
        
        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypt_fail.png',
            $key
        );
        
        $fp = \fopen(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 'ab');
        \fwrite($fp, \random_bytes(1));
        fclose($fp);
            
        try {
            File::decrypt(
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

    /**
     * @covers File::encrypt()
     * @covers File::decrypt()
     */
    public function testEncryptSmallFail()
    {
        $msg = 'Input file is too small to have been encrypted by Halite.';
        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );

        \file_put_contents(
            __DIR__.'/tmp/empty.encrypted.txt',
            ''
        );
        try {
            File::decrypt(
                __DIR__ . '/tmp/empty.encrypted.txt',
                __DIR__ . '/tmp/empty.decrypted.txt',
                $key
            );
            $this->fail("This should scream bloody murder");
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertSame($msg, $e->getMessage());
        }

        \file_put_contents(
            __DIR__.'/tmp/empty.encrypted.txt',
            "\x31\x41\x03\x00\x01"
        );
        try {
            File::decrypt(
                __DIR__ . '/tmp/empty.encrypted.txt',
                __DIR__ . '/tmp/empty.decrypted.txt',
                $key
            );
            $this->fail("This should scream bloody murder");
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertSame($msg, $e->getMessage());
        }


        \file_put_contents(
            __DIR__.'/tmp/empty.encrypted.txt',
            "\x31\x41\x03\x00" . \str_repeat("\x00", 87)
        );
        try {
            File::decrypt(
                __DIR__ . '/tmp/empty.encrypted.txt',
                __DIR__ . '/tmp/empty.decrypted.txt',
                $key
            );
            $this->fail("This should scream bloody murder");
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertSame($msg, $e->getMessage());
        }

        \unlink(__DIR__.'/tmp/empty.encrypted.txt');
        \unlink(__DIR__.'/tmp/empty.decrypted.txt');
    }

    /**
     * @covers File::seal()
     * @covers File::unseal()
     */
    public function testSeal()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        File::seal(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            $publickey
        );
        
        File::unseal(
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            __DIR__.'/tmp/paragon_avatar.opened.png',
            $secretkey
        );
        
        $this->assertSame(
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            \hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );
        
        \unlink(__DIR__.'/tmp/paragon_avatar.sealed.png');
        \unlink(__DIR__.'/tmp/paragon_avatar.opened.png');
    }

    /**
     * @covers File::seal()
     * @covers File::unseal()
     */
    public function testSealEmpty()
    {
        \file_put_contents(__DIR__.'/tmp/empty.txt', '');
        \chmod(__DIR__.'/tmp/empty.txt', 0777);

        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();

        File::seal(
            __DIR__.'/tmp/empty.txt',
            __DIR__.'/tmp/empty.sealed.txt',
            $publickey
        );

        File::unseal(
            __DIR__.'/tmp/empty.sealed.txt',
            __DIR__.'/tmp/empty.unsealed.txt',
            $secretkey
        );

        $this->assertSame(
            \hash_file('sha256', __DIR__.'/tmp/empty.txt'),
            \hash_file('sha256', __DIR__.'/tmp/empty.unsealed.txt')
        );

        \unlink(__DIR__.'/tmp/empty.txt');
        \unlink(__DIR__.'/tmp/empty.sealed.txt');
        \unlink(__DIR__.'/tmp/empty.unsealed.txt');
    }

    /**
     * @covers File::seal()
     * @covers File::unseal()
     */
    public function testSealFail()
    {
        \touch(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 0777);
        \touch(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        \chmod(__DIR__.'/tmp/paragon_avatar.open_fail.png', 0777);
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        File::seal(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.seal_fail.png',
            $publickey
        );
        
        $fp = \fopen(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 'ab');
        \fwrite($fp, \random_bytes(1));
        \fclose($fp);
        
        try {
            File::unseal(
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

    /**
     * @covers File::seal()
     * @covers File::unseal()
     */
    public function testSealSmallFail()
    {
        $msg = 'Input file is too small to have been encrypted by Halite.';
        $keypair = KeyFactory::generateEncryptionKeyPair();
        $secretkey = $keypair->getSecretKey();

        \file_put_contents(__DIR__.'/tmp/empty.sealed.txt', '');

        try {
            File::unseal(
                __DIR__.'/tmp/empty.sealed.txt',
                __DIR__.'/tmp/empty.unsealed.txt',
                $secretkey
            );
            $this->fail("This should scream bloody murder");
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertSame($msg, $e->getMessage());
        }

        \file_put_contents(
            __DIR__.'/tmp/empty.sealed.txt',
            "\x31\x41\x03\x00" . \str_repeat("\x00", 95)
        );
        try {
            File::unseal(
                __DIR__.'/tmp/empty.sealed.txt',
                __DIR__.'/tmp/empty.unsealed.txt',
                $secretkey
            );
            $this->fail("This should scream bloody murder");
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertSame($msg, $e->getMessage());
        }

        \unlink(__DIR__.'/tmp/empty.sealed.txt');
        \unlink(__DIR__.'/tmp/empty.unsealed.txt');
    }

    /**
     * @covers File::sign()
     * @covers File::verify()
     */
    public function testSign()
    {
        $keypair = KeyFactory::generateSignatureKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        $signature = File::sign(
            __DIR__.'/tmp/paragon_avatar.png',
            $secretkey
        );
        
        $this->assertTrue(
            File::verify(
                __DIR__.'/tmp/paragon_avatar.png',
                $publickey,
                $signature
            )
        );
    }

    /**
     * @covers File::checksum()
     */
    public function testChecksum()
    {
        $csum = File::checksum(__DIR__.'/tmp/paragon_avatar.png', null, false);
        $this->assertSame(
            $csum,
            "09f9f74a0e742d057ca08394db4c2e444be88c0c94fe9a914c3d3758c7eccafb".
            "8dd286e3d6bc37f353e76c0c5aa2036d978ca28ffaccfa59f5dc1f076c5517a0"
        );
        
        $data = \random_bytes(32);
        \file_put_contents(__DIR__.'/tmp/garbage.dat', $data);
        
        $hash = Util::raw_hash($data, 64);
        $file = File::checksum(__DIR__.'/tmp/garbage.dat', null, true);
        $this->assertSame(
            $hash,
            $file
        );
        \unlink(__DIR__.'/tmp/garbage.dat');
    }
}
