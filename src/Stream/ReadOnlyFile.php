<?php
namespace ParagonIE\Halite\Stream;

use \ParagonIE\Halite\Contract\StreamInterface;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util;

class ReadOnlyFile implements StreamInterface
{
    const CHUNK = 8192; // PHP's fread() buffer is set to 8192 by default

    /** @var resource */
    private $fp;

    /** @var string */
    private $hash;

    /** @var int */
    private $pos;

    /** @var array */
    private $stat = [];

    /**
     * ReadOnlyFile constructor.
     *
     * @param string|resource $file
     * @throws CryptoException\InvalidType
     * @throws CryptoException\FileAccessDenied
     */
    public function __construct($file)
    {
        if (\is_string($file)) {
            /** @var resource $fp */
            $fp = \fopen($file, 'rb');
            if (!\is_resource($fp)) {
                throw new CryptoException\FileAccessDenied('Cannot open file');
            }
            $this->fp = $fp;
            $this->pos = 0;
            $this->stat = \fstat($this->fp);
        } elseif (\is_resource($file)) {
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = \fstat($this->fp);
        } else {
            throw new \ParagonIE\Halite\Alerts\InvalidType(
                'Argument 1: Expected a filename or resource'
            );
        }
        $this->hash = $this->getHash();
    }
    
    /**
     * Where are we in the buffer?
     * 
     * @return int
     */
    public function getPos()
    {
        return (int) $this->pos;
    }
    /**
     * How big is this buffer?
     * 
     * @return int
     */
    public function getSize()
    {
        return (int) $this->stat['size'];
    }
    
    /**
     * Read from a stream; prevent partial reads (also uses run-time testing to
     * prevent partial reads -- you can turn this off if you need performance
     * and aren't concerned about race condition attacks, but this isn't a
     * decision to make lightly!)
     * 
     * @param int $num
     * @param boolean $skipTests Only set this to TRUE if you're absolutely sure
     *                           that you don't want to defend against TOCTOU /
     *                           race condition attacks on the filesystem!
     * @return string
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
     */
    public function readBytes($num, $skipTests = false)
    {
        if ($num < 0) {
            throw new CryptoException\CannotPerformOperation('num < 0');
        } elseif ($num === 0) {
            return '';
        }
        if (($this->pos + $num) > $this->stat['size']) {
            throw new CryptoException\CannotPerformOperation('Out-of-bounds read');
        }
        $buf = '';
        $remaining = $num;
        if (!$skipTests) {
            $this->toctouTest();
        }
        do {
            if ($remaining <= 0) {
                break;
            }
            $read = \fread($this->fp, $remaining);
            if (!\is_string($read)) {
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
        return (int) (PHP_INT_MAX & ((int) $this->stat['size'] - $this->pos));
    }
    
    /**
     * This is a meaningless operation for a Read-Only File!
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @return void
     * @throws CryptoException\FileAccessDenied
     */
    public function writeBytes($buf, $num = null)
    {
        unset($buf);
        unset($num);
        throw new CryptoException\FileAccessDenied(
            'This is a read-only file handle.'
        );
    }
    
    /**
     * Set the current cursor position to the desired location
     * 
     * @param int $i
     * @return bool
     * @throws CryptoException\CannotPerformOperation
     */
    public function reset($i = 0)
    {
        $this->pos = $i;
        if (\fseek($this->fp, $i, SEEK_SET) === 0) {
            return true;
        }
        throw new CryptoException\CannotPerformOperation(
            'fseek() failed'
        );
    }
    
    /**
     * Calculate a BLAKE2b hash of a file
     * 
     * @return string
     */
    public function getHash()
    {
        $init = $this->pos;
        \fseek($this->fp, 0, SEEK_SET);
        
        // Create a hash context:
        /** @var string $h */
        $h = \Sodium\crypto_generichash_init(
            null,
            \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
        );
        for ($i = 0; $i < $this->stat['size']; $i += self::CHUNK) {
            if (($i + self::CHUNK) > $this->stat['size']) {
                $c = \fread($this->fp, ((int) $this->stat['size'] - $i));
            } else {
                $c = \fread($this->fp, self::CHUNK);
            }
            \Sodium\crypto_generichash_update($h, $c);
        }
        // Reset the file pointer's internal cursor to where it was:
        \fseek($this->fp, $init, SEEK_SET);
        return (string) \Sodium\crypto_generichash_final($h);
    }
    
    /**
     * Run-time test to prevent TOCTOU attacks (race conditions) through
     * verifying that the hash matches and the current cursor position/file
     * size matches their values when the file was first opened.
     * 
     * @throws CryptoException\FileModified
     * @return bool
     */
    public function toctouTest()
    {
        if (\ftell($this->fp) !== $this->pos) {
            throw new CryptoException\FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
        $stat = \fstat($this->fp);
        if ($stat['size'] !== $this->stat['size']) {
            throw new CryptoException\FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
        return true;
    }
}
