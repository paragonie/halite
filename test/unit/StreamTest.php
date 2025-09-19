<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Stream\{
    MutableFile,
    ReadOnlyFile
};
use PHPUnit\Framework\TestCase;

final class StreamTest extends TestCase
{
    /**
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testFileHash()
    {
        $filename = @tempnam('/tmp', 'x');
        
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);
        
        $fileOne = new ReadOnlyFile($filename);
        $fp = fopen($filename, 'rb');
        $fileTwo = new ReadOnlyFile($fp);
        
        $this->assertSame(
            $fileOne->getHash(),
            $fileTwo->getHash()
        );
        $this->assertSame(65537, $fileOne->getSize());

        fclose($fp);
    }

    /**
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testUnreadableFile()
    {
        $filename = @tempnam('/tmp', 'x');
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);
        chmod($filename, 0000);
        $perms = fileperms($filename);
        if (!is_int($perms) || ($perms & 0777) !== 0 || is_readable($filename)) {
            $this->markTestSkipped('chmod failed to remove read access, so the test will fail; skipping');
        }

        try {
            new ReadOnlyFile($filename);
            if (DIRECTORY_SEPARATOR === '\\') {
                $this->markTestSkipped('Windows permissions are weird.');
            }
            $this->fail('File should not be readable');
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame('Could not open file for reading', $ex->getMessage());
        }
        try {
            new MutableFile($filename);
            $this->fail('File should not be readable');
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame('Could not open file for reading', $ex->getMessage());
        }

        chmod($filename, 0444);
        try {
            new MutableFile($filename);
            $this->fail('File should not be writeable');
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame('Could not open file for writing', $ex->getMessage());
        }
        unlink($filename);

        try {
            new ReadOnlyFile('/etc/shadow');
            $this->fail('File should not be readable');
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame('Could not open file for reading', $ex->getMessage());
        }
    }

    /**
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testResource()
    {
        $filename = @tempnam('/tmp', 'x');
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);

        $file = \fopen($filename, 'rb');
        $stream = new ReadOnlyFile($file);
        $this->assertInstanceOf(ReadOnlyFile::class, $stream);

        try {
            new MutableFile($file);
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame(
                'Resource is in rb mode, which is not allowed.',
                $ex->getMessage()
            );
        }

        $writable = \fopen($filename, 'w+b');
        $wstream = new MutableFile($writable);
        $this->assertInstanceOf(MutableFile::class, $wstream);
        try {
            new ReadOnlyFile($writable);
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame(
                'Resource is in w+b mode, which is not allowed.',
                $ex->getMessage()
            );
        }

        try {
            new ReadOnlyFile(12345);
            $this->fail('Invalid file type accepted');
        } catch (CryptoException\InvalidType $ex) {
        }
        try {
            new MutableFile(12345);
            $this->fail('Invalid file type accepted');
        } catch (CryptoException\InvalidType $ex) {
        }
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\FileModified
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testFileRead()
    {
        $filename = @tempnam('/tmp', 'x');
        
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);

        $fStream = new ReadOnlyFile($filename);
        
        $this->assertSame(
            $fStream->readBytes(65537),
            $buf
        );
        $fStream->reset(0);

        try {
            $fStream->readBytes(-1);
            $this->fail('Allowed to read -1 bytes');
        } catch (CryptoException\CannotPerformOperation $ex) {
        }
        try {
            $fStream->readBytes(65538);
            $this->fail('Allowed to read more bytes than the file contains');
        } catch (CryptoException\CannotPerformOperation $ex) {
        }
        
        file_put_contents(
            $filename,
            Binary::safeSubstr($buf, 0, 32768) . 'x' . Binary::safeSubstr($buf, 32768)
        );
        
        try {
            $fStream->readBytes(65537);
            $this->fail('File was mutated after being read');
        } catch (CryptoException\FileModified $ex) {
            $this->assertInstanceOf(CryptoException\FileModified::class, $ex);
        }

        $fStream = new ReadOnlyFile($filename);
        try {
            $fStream->writeBytes('test');
            $this->fail('Attempt to write to ReadOnlyFile should raise exception.');
        } catch (CryptoException\FileAccessDenied $ex) {
        }

        foreach ([255, 65537] as $size) {
            $buffer = random_bytes($size);
            $fileWrite = @tempnam('/tmp', 'x');
            $mStream = new MutableFile($fileWrite);
            $mStream->writeBytes($buffer);
            $mStream->reset(0);

            $this->assertSame(0, $mStream->getPos());
            $this->assertSame($size, $mStream->remainingBytes());

            $mStream->reset(127);
            $this->assertSame($size - 127, $mStream->remainingBytes());
            $mStream->reset(0);

            $this->assertSame($size, $mStream->getSize());
            $this->assertSame(bin2hex($buffer), bin2hex($mStream->readBytes($size)));
        }
    }


    public function testMutableFileResource()
    {
        $fp = fopen('php://temp', 'w+b');
        $mStream = new MutableFile($fp);
        $mStream->writeBytes('test');
        $mStream->reset();
        $this->assertSame('test', $mStream->readBytes(4));
    }

    /**
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\InvalidType
     */
    public function testWriteBytesNull(): void
    {
        $mStream = new MutableFile(fopen('php://temp', 'w+b'));
        $this->assertSame(4, $mStream->writeBytes('test', null));
    }

    /**
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws SodiumException
     */
    public function testReadOnlyFileResource(): void
    {
        $fp = fopen('php://temp', 'rb');
        $rStream = new ReadOnlyFile($fp);
        $this->assertInstanceOf(ReadOnlyFile::class, $rStream);
    }

    /**
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws SodiumException
     */
    public function testReadOnlyFileWriteBytes(): void
    {
        $this->expectException(CryptoException\FileAccessDenied::class);
        $rStream = new ReadOnlyFile(fopen('php://temp', 'rb'));
        $rStream->writeBytes('test');
    }
}
