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
     * @throws TypeError
     */
    public function testFileHash()
    {
        $filename = tempnam('/tmp', 'x');
        
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);
        
        $fileOne = new ReadOnlyFile($filename);
        $fp = fopen($filename, 'rb');
        $fileTwo = new ReadOnlyFile($fp);
        
        $this->assertSame(
            $fileOne->getHash(),
            $fileTwo->getHash()
        );
        fclose($fp);
    }

    /**
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testUnreadableFile()
    {
        $filename = tempnam('/tmp', 'x');
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);
        chmod($filename, 0000);

        try {
            new ReadOnlyFile($filename);
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
    }

    /**
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\FileError
     * @throws CryptoException\InvalidType
     * @throws TypeError
     */
    public function testResource()
    {
        $filename = tempnam('/tmp', 'x');
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

        $writable = \fopen($filename, 'wb');
        try {
            new ReadOnlyFile($writable);
        } catch (CryptoException\FileAccessDenied $ex) {
            $this->assertSame(
                'Resource is in wb mode, which is not allowed.',
                $ex->getMessage()
            );
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
        $filename = tempnam('/tmp', 'x');
        
        $buf = random_bytes(65537);
        file_put_contents($filename, $buf);

        $fStream = new ReadOnlyFile($filename);
        
        $this->assertSame(
            $fStream->readBytes(65537),
            $buf
        );
        $fStream->reset(0);
        
        file_put_contents(
            $filename,
            Binary::safeSubstr($buf, 0, 32768) . 'x' . Binary::safeSubstr($buf, 32768)
        );
        
        try {
            $fStream->readBytes(65537);
            throw new Exception('fail');
        } catch (CryptoException\FileModified $ex) {
            $this->assertTrue(
                $ex instanceof CryptoException\FileModified
            );
        }
    }
}
