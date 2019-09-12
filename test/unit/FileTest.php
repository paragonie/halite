<?php
declare(strict_types=1);

use ParagonIE\Halite\File;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Stream\{
    MutableFile,
    ReadOnlyFile,
    WeakReadOnlyFile
};
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Halite\Util;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

final class FileTest extends TestCase
{

    public function setUp(): void
    {
        chmod(__DIR__.'/tmp/', 0777);
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testEncrypt()
    {
        touch(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        chmod(__DIR__.'/tmp/paragon_avatar.encrypted.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.decrypted.png');
        chmod(__DIR__.'/tmp/paragon_avatar.decrypted.png', 0777);

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
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.decrypted.png')
        );
        unlink(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        unlink(__DIR__.'/tmp/paragon_avatar.decrypted.png');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testEncryptEmpty()
    {
        file_put_contents(__DIR__.'/tmp/empty.txt', '');
        chmod(__DIR__.'/tmp/empty.txt', 0777);
        touch(__DIR__.'/tmp/empty.encrypted.txt');
        chmod(__DIR__.'/tmp/empty.encrypted.txt', 0777);
        touch(__DIR__.'/tmp/empty.decrypted.txt');
        chmod(__DIR__.'/tmp/empty.decrypted.txt', 0777);

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
            hash_file('sha256', __DIR__.'/tmp/empty.txt'),
            hash_file('sha256', __DIR__.'/tmp/empty.decrypted.txt')
        );
        unlink(__DIR__.'/tmp/empty.txt');
        unlink(__DIR__.'/tmp/empty.encrypted.txt');
        unlink(__DIR__.'/tmp/empty.decrypted.txt');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testEncryptFail()
    {
        touch(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
        chmod(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        chmod(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png', 0777);
        
        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypt_fail.png',
            $key
        );
        
        $fp = fopen(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png', 'ab');
        fwrite($fp, random_bytes(1));
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
            unlink(__DIR__.'/tmp/paragon_avatar.encrypt_fail.png');
            unlink(__DIR__.'/tmp/paragon_avatar.decrypt_fail.png');
        }

        try {
            File::encrypt(true, false, $key);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
        try {
            File::decrypt(true, false, $key);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testEncryptSmallFail()
    {
        touch(__DIR__.'/tmp/empty.encrypted.txt');
        chmod(__DIR__.'/tmp/empty.encrypted.txt', 0777);
        touch(__DIR__.'/tmp/empty.decrypted.txt');
        chmod(__DIR__.'/tmp/empty.decrypted.txt', 0777);

        $msg = 'Input file is too small to have been encrypted by Halite.';
        $key = new EncryptionKey(
            new HiddenString(str_repeat('B', 32))
        );

        file_put_contents(
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

        file_put_contents(
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


        file_put_contents(
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

        unlink(__DIR__.'/tmp/empty.encrypted.txt');
        unlink(__DIR__.'/tmp/empty.decrypted.txt');
    }
    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testEncryptVarious()
    {
        touch(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        chmod(__DIR__.'/tmp/paragon_avatar.encrypted.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.decrypted.png');
        chmod(__DIR__.'/tmp/paragon_avatar.decrypted.png', 0777);

        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.encrypted.png'),
            $key
        );

        File::decrypt(
            new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.encrypted.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.decrypted.png'),
            $key
        );

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.decrypted.png')
        );

        File::encrypt(
            new WeakReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.encrypted.png'),
            $key
        );

        File::decrypt(
            new WeakReadOnlyFile(__DIR__.'/tmp/paragon_avatar.encrypted.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.decrypted.png'),
            $key
        );

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.decrypted.png')
        );
        unlink(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        unlink(__DIR__.'/tmp/paragon_avatar.decrypted.png');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testSeal()
    {
        touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);
        
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
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );
        
        unlink(__DIR__.'/tmp/paragon_avatar.sealed.png');
        unlink(__DIR__.'/tmp/paragon_avatar.opened.png');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testSealFromStreamWrapper()
    {
        require_once __DIR__ . '/RemoteStream.php';
        stream_register_wrapper('haliteTest', RemoteStream::class);
        touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);

        $keypair = KeyFactory::generateEncryptionKeyPair();
        $secretkey = $keypair->getSecretKey();
        $publickey = $keypair->getPublicKey();

        $file = new ReadOnlyFile(fopen('haliteTest://paragon_avatar.png', 'rb'));
        File::seal(
          $file,
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            $publickey
        );

        File::unseal(
            __DIR__.'/tmp/paragon_avatar.sealed.png',
            __DIR__.'/tmp/paragon_avatar.opened.png',
            $secretkey
        );

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );

        unlink(__DIR__.'/tmp/paragon_avatar.sealed.png');
        unlink(__DIR__.'/tmp/paragon_avatar.opened.png');
        $this->assertEquals($file->getHash(), (new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png'))->getHash());
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testSealEmpty()
    {
        file_put_contents(__DIR__.'/tmp/empty.txt', '');
        chmod(__DIR__.'/tmp/empty.txt', 0777);
        touch(__DIR__.'/tmp/empty.sealed.txt');
        chmod(__DIR__.'/tmp/empty.sealed.txt', 0777);
        touch(__DIR__.'/tmp/empty.unsealed.txt');
        chmod(__DIR__.'/tmp/empty.unsealed.txt', 0777);

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
            hash_file('sha256', __DIR__.'/tmp/empty.txt'),
            hash_file('sha256', __DIR__.'/tmp/empty.unsealed.txt')
        );

        unlink(__DIR__.'/tmp/empty.txt');
        unlink(__DIR__.'/tmp/empty.sealed.txt');
        unlink(__DIR__.'/tmp/empty.unsealed.txt');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testSealFail()
    {
        touch(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
        chmod(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        chmod(__DIR__.'/tmp/paragon_avatar.open_fail.png', 0777);
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $secretkey = $keypair->getSecretKey();
            $publickey = $keypair->getPublicKey();
        
        File::seal(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.seal_fail.png',
            $publickey
        );
        
        $fp = fopen(__DIR__.'/tmp/paragon_avatar.seal_fail.png', 'ab');
        fwrite($fp, random_bytes(1));
        fclose($fp);
        
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
            unlink(__DIR__.'/tmp/paragon_avatar.seal_fail.png');
            unlink(__DIR__.'/tmp/paragon_avatar.open_fail.png');
        }

        try {
            File::seal(true, false, $publickey);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
        try {
            File::unseal(true, false, $secretkey);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testSealSmallFail()
    {
        touch(__DIR__.'/tmp/empty.sealed.txt');
        chmod(__DIR__.'/tmp/empty.sealed.txt', 0777);
        touch(__DIR__.'/tmp/empty.unsealed.txt');
        chmod(__DIR__.'/tmp/empty.unsealed.txt', 0777);

        $msg = 'Input file is too small to have been encrypted by Halite.';
        $keypair = KeyFactory::generateEncryptionKeyPair();
        $secretkey = $keypair->getSecretKey();

        file_put_contents(__DIR__.'/tmp/empty.sealed.txt', '');

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

        file_put_contents(
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

        unlink(__DIR__.'/tmp/empty.sealed.txt');
        unlink(__DIR__.'/tmp/empty.unsealed.txt');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testSealVarious()
    {
        touch(__DIR__.'/tmp/paragon_avatar.sealed.png');
        chmod(__DIR__.'/tmp/paragon_avatar.sealed.png', 0777);
        touch(__DIR__.'/tmp/paragon_avatar.opened.png');
        chmod(__DIR__.'/tmp/paragon_avatar.opened.png', 0777);

        $keypair = KeyFactory::generateEncryptionKeyPair();
        $secretkey = $keypair->getSecretKey();
        $publickey = $keypair->getPublicKey();

        File::seal(
            new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.sealed.png'),
            $publickey
        );

        File::unseal(
            new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.sealed.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.opened.png'),
            $secretkey
        );

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );

        File::seal(
            new WeakReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.sealed.png'),
            $publickey
        );

        File::unseal(
            new WeakReadOnlyFile(__DIR__.'/tmp/paragon_avatar.sealed.png'),
            new MutableFile(__DIR__.'/tmp/paragon_avatar.opened.png'),
            $secretkey
        );

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.opened.png')
        );

        unlink(__DIR__.'/tmp/paragon_avatar.sealed.png');
        unlink(__DIR__.'/tmp/paragon_avatar.opened.png');
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     * @throws TypeError
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

        try {
            File::sign(true, $secretkey);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
        try {
            File::verify(false, $publickey, '');
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testSignVarious()
    {
        $keypair = KeyFactory::generateSignatureKeyPair();
        $secretkey = $keypair->getSecretKey();
        $publickey = $keypair->getPublicKey();

        $inputFile = new ReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png');

        $signature = File::sign(
            $inputFile,
            $secretkey
        );

        $this->assertTrue(
            File::verify(
                $inputFile,
                $publickey,
                $signature
            )
        );

        $mutable = new WeakReadOnlyFile(__DIR__.'/tmp/paragon_avatar.png');
        $signature = File::sign(
            $mutable,
            $secretkey
        );

        $this->assertTrue(
            File::verify(
                $mutable,
                $publickey,
                $signature
            )
        );
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidMessage
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testChecksum()
    {
        $csum = File::checksum(__DIR__.'/tmp/paragon_avatar.png', null, false);
        $this->assertSame(
            $csum,
            "09f9f74a0e742d057ca08394db4c2e444be88c0c94fe9a914c3d3758c7eccafb".
            "8dd286e3d6bc37f353e76c0c5aa2036d978ca28ffaccfa59f5dc1f076c5517a0"
        );
        
        $data = random_bytes(32);
        file_put_contents(__DIR__.'/tmp/garbage.dat', $data);
        
        $hash = Util::raw_hash($data, 64);
        $file = File::checksum(__DIR__.'/tmp/garbage.dat', null, true);
        $this->assertSame(
            $hash,
            $file
        );
        $this->assertSame(
            $hash,
            File::checksum(new ReadOnlyFile(__DIR__.'/tmp/garbage.dat'), null, true)
        );
        $this->assertSame(
            $hash,
            File::checksum(new WeakReadOnlyFile(__DIR__.'/tmp/garbage.dat'), null, true)
        );

        // No exceptions:
        File::checksum(__DIR__.'/tmp/garbage.dat', KeyFactory::generateAuthenticationKey(), true);
        File::checksum(__DIR__.'/tmp/garbage.dat', KeyFactory::generateSignatureKeyPair()->getPublicKey(), true);

        try {
            File::checksum(false);
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidType $ex) {
        }
        try {
            File::checksum(__DIR__.'/tmp/garbage.dat', KeyFactory::generateEncryptionKey());
            $this->fail('Invalid type was accepted.');
        } catch (CryptoException\InvalidKey $ex) {
        }

        unlink(__DIR__.'/tmp/garbage.dat');
    }

    public function testNonExistingOutputFile()
    {
        file_put_contents(__DIR__.'/tmp/empty116.txt', '');
        if (\is_file(__DIR__ . '/tmp/empty116.encrypted.txt')) {
            \unlink(__DIR__ . '/tmp/empty116.encrypted.txt');
            \clearstatcache();
        }
        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/empty116.txt',
            __DIR__.'/tmp/empty116.encrypted.txt',
            $key
        );
        $this->assertTrue(\file_exists(__DIR__.'/tmp/empty116.encrypted.txt'));
    }

    public function testOutputToOutputbuffer()
    {
        $stream = fopen('php://output', 'wb');

        touch(__DIR__.'/tmp/paragon_avatar.encrypted.png');
        chmod(__DIR__.'/tmp/paragon_avatar.encrypted.png', 0777);

        $key = new EncryptionKey(
            new HiddenString(\str_repeat('B', 32))
        );
        File::encrypt(
            __DIR__.'/tmp/paragon_avatar.png',
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            $key
        );

        ob_start();
        File::decrypt(
            __DIR__.'/tmp/paragon_avatar.encrypted.png',
            $stream,
            $key
        );
        $contents = ob_get_clean();

        $this->assertSame(
            hash_file('sha256', __DIR__.'/tmp/paragon_avatar.png'),
            hash('sha256', $contents)
        );
        unlink(__DIR__.'/tmp/paragon_avatar.encrypted.png');
    }
}
