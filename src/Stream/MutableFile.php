<?php
namespace ParagonIE\Halite\Stream;

use \ParagonIE\Halite\Contract\StreamInterface;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util;

/**
 * Contrast with ReadOnlyFile: does not prevent race conditions by itself
 */
class MutableFile implements StreamInterface
{
    const CHUNK = 8192; // PHP's fread() buffer is set to 8192 by default

    /** @var resource $fp */
    private $fp;

    /** @var int $pos*/
    private $pos;

    /** @var array */
    private $stat = [];

    /**
     * MutableFile constructor.
     *
     * @param string|resource $file
     * @throws CryptoException\InvalidType
     * @throws CryptoException\FileAccessDenied
     */
    public function __construct($file)
    {
        if (\is_string($file)) {
            $fp = \fopen($file, 'wb');
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
    }
    
    /**
     * Read from a stream; prevent partial reads
     * 
     * @param int $num
     * @return string
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
     */
    public function readBytes($num)
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
     * Write to a stream; prevent partial writes
     * 
     * @param resource $stream
     * @param string $buf
     * @param int $num (number of bytes)
     * @return int
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
     */
    public function writeBytes($buf, $num = null)
    {
        $bufSize = Util::safeStrlen($buf);
        if ($num === null || $num > $bufSize) {
            $num = $bufSize;
        }
        if ($num < 0) {
            throw new CryptoException\CannotPerformOperation('num < 0');
        }
        $remaining = $num;
        do {
            if ($remaining <= 0) {
                break;
            }
            $written = \fwrite($this->fp, $buf, $remaining);
            if ($written === false) {
                throw new CryptoException\FileAccessDenied(
                    'Could not write to the file'
                );
            }
            $buf = Util::safeSubstr($buf, $written, null);
            $this->pos += $written;
            $this->stat = \fstat($this->fp);
            $remaining -= $written;
        } while ($remaining > 0);
        return $num;
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
     * Get number of bytes remaining
     *
     * @return int
     */
    public function remainingBytes()
    {
        return (int) (PHP_INT_MAX & ((int) $this->stat['size'] - $this->pos));
    }
    
    /**
     * Set the current cursor position to the desired location
     * 
     * @param int $i
     * 
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
}
