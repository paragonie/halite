<?php
namespace ParagonIE\Halite\Stream;

use \ParagonIE\Halite\Contract\StreamInterface;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util;

class ReadOnlyFile implements StreamInterface
{
    const CHUNK = 8192; // PHP's fread() buffer is set to 8192 by default
    
    private $fp;
    private $hash;
    private $pos;
    private $stat = [];
    
    public function __construct($file)
    {
        if (is_string($file)) {
            $this->fp = \fopen($file, 'rb');
            $this->pos = 0;
            $this->stat = \fstat($this->fp);
        } elseif (is_resource($file)) {
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = \fstat($this->fp);
        }
        $this->hash = $this->getHash();
    }
    
    /**
     * Where are we in the buffeR?
     * 
     * @return int
     */
    public function getPos()
    {
        return $this->pos;
    }
    /**
     * How big is this buffer?
     * 
     * @return int
     */
    public function getSize()
    {
        return $this->stat['size'];
    }
    
    /**
     * Read from a stream; prevent partial reads
     * 
     * @param int $num
     * @return string
     * @throws FileAlert\AccessDenied
     */
    public function readBytes($num)
    {
        if ($num <= 0) {
            throw new \Exception('num < 0');
        }
        if (($this->pos + $num) > $this->stat['size']) {
            throw new \Exception('Out-of-bounds read');
        }
        $buf = '';
        $remaining = $num;
        $this->toctouTest();
        do {
            if ($remaining <= 0) {
                break;
            }
            $read = \fread($this->fp, $remaining);
            if ($read === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not read from the file'
                );
            }
            $buf .= $read;
            $readSize = Util::safeStrlen($read);
            $this->pos += $readSize;
            $remaining -= $readSize;
        } while ($remaining > 0);
        return $buf;
    }
    
    /**
     * Get number of bytes remaining
     * 
     * @return int
     */
    public function remainingBytes()
    {
        return (PHP_INT_MAX & ($this->stat['size'] - $this->pos));
    }
    
    /**
     * Write to a stream; prevent partial writes
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @throws FileAlert\AccessDenied
     */
    public function writeBytes($buf, $num = null)
    {
        throw new CryptoException\FileAccessDenied(
            'This is a read-only file handle.'
        );
    }
    
    public function reset($i = 0)
    {
        $this->pos = $i;
        \fseek($this->fp, $i, SEEK_SET);
    }
    
    /**
     * Calculate a hash of a file
     * 
     * @return string
     */
    public function getHash()
    {
        $init = $this->pos;
        \fseek($this->fp, 0, SEEK_SET);
        $h = \Sodium\crypto_generichash_init(
            null,
            \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
        );
        $i = 0;
        for ($i = 0; $i < $this->stat['size']; $i += self::CHUNK) {
            if (($i + self::CHUNK) > $this->stat['size']) {
                $c = \fread($this->fp, ($this->stat['size'] - $i));
            } else {
                $c = \fread($this->fp, self::CHUNK);
            }
            \Sodium\crypto_generichash_update($h, $c);
        }
        \fseek($this->fp, $init, SEEK_SET);
        return \Sodium\crypto_generichash_final($h);
    }
    
    /**
     * Run-time test to prevent TOCTOU attacks (race conditions)
     * 
     * @throws CryptoException\FileModified
     * @return true
     */
    public function toctouTest()
    {
        if (!\hash_equals($this->hash, $this->getHash())) {
            throw new CryptoException\FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
        return true;
    }
}