<?php

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Stream\ReadOnlyFile;
use \ParagonIE\Halite\Util;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class StreamTest extends PHPUnit_Framework_TestCase
{
    public function testFileHash()
    {
        $filename = \tempnam('/tmp', 'x');
        
        $buf = \Sodium\randombytes_buf(65537);
        \file_put_contents($filename, $buf);
        
        $fileOne = new ReadOnlyFile($filename);
        $fp = \fopen($filename, 'rb');
        $fileTwo = new ReadOnlyFile($fp);
        
        $this->assertEquals(
            $fileOne->getHash(),
            $fileTwo->getHash()
        );
        \fclose($fp);
    }
    
    public function testFileRead()
    {
        $filename = \tempnam('/tmp', 'x');
        
        $buf = \Sodium\randombytes_buf(65537);
        \file_put_contents($filename, $buf);
        
        $fStream = new ReadOnlyFile($filename);
        
        $this->assertEquals(
            $fStream->readBytes(65537),
            $buf
        );
        $fStream->reset(0);
        
        \file_put_contents(
            $filename,
            Util::safeSubstr($buf, 0, 32768) . 'x' . Util::safeSubstr($buf, 32768)
        );
        
        try {
            $x = $fStream->readBytes(65537);
            throw new \Exception('fail');
        } catch (CryptoException\FileModified $ex) {
            $this->assertTrue(
                $ex instanceof CryptoException\FileModified
            );
        }
    }
}