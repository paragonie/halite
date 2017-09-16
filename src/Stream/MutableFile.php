<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Util as CryptoUtil;

/**
 * Class MutableFile
 *
 * Contrast with ReadOnlyFile: does not prevent race conditions by itself
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Stream
 */
class MutableFile implements StreamInterface
{
    const CHUNK = 8192; // PHP's fread() buffer is set to 8192 by default

    /**
     * @var bool
     */
    private $closeAfter = false;

    /**
     * @var resource
     */
    private $fp;

    /**
     * @var int
     */
    private $pos;

    /**
     * @var array
     */
    private $stat = [];

    /**
     * MutableFile constructor.
     * @param string|resource $file
     * @throws CryptoException\InvalidType
     * @throws CryptoException\FileAccessDenied
     */
    public function __construct($file)
    {
        if (\is_string($file)) {
            $fp = \fopen($file, 'wb');
            if (!\is_resource($fp)) {
                throw new CryptoException\FileAccessDenied(
                    'Could not open file for reading'
                );
            }
            $this->fp = $fp;
            $this->closeAfter = true;
            $this->pos = 0;
            $this->stat = \fstat($this->fp);
        } elseif (\is_resource($file)) {
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = \fstat($this->fp);
        } else {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected a filename or resource'
            );
        }
    }

    /**
     * Close the file handle.
     */
    public function close(): void
    {
        if ($this->closeAfter) {
            $this->closeAfter = false;
            \fclose($this->fp);
            \clearstatcache();
        }
    }

    /**
     * Make sure we invoke $this->close()
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * Where are we in the buffer?
     *
     * @return int
     */
    public function getPos(): int
    {
        return \ftell($this->fp);
    }

    /**
     * How big is this buffer?
     *
     * @return int
     */
    public function getSize(): int
    {
        $stat = \fstat($this->fp);
        return $stat['size'];
    }

    /**
     * Read from a stream; prevent partial reads
     *
     * @param int $num
     * @param bool $skipTests
     * @return string
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\FileAccessDenied
     */
    public function readBytes(int $num, bool $skipTests = false): string
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
            /** @var string $read */
            $read = \fread($this->fp, $remaining);
            if (!\is_string($read)) {
                throw new CryptoException\FileAccessDenied(
                    'Could not read from the file'
                );
            }
            $buf .= $read;
            $readSize = CryptoUtil::safeStrlen($read);
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
    public function remainingBytes(): int
    {
        $stat = \fstat($this->fp);
        $pos = \ftell($this->fp);
        return (PHP_INT_MAX & ($stat['size'] - $pos));
    }
    
    /**
     * Set the current cursor position to the desired location
     * 
     * @param int $i
     * @return bool
     * @throws CryptoException\CannotPerformOperation
     */
    public function reset(int $i = 0): bool
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
     * Write to a stream; prevent partial writes
     *
     * @param string $buf
     * @param int $num (number of bytes)
     * @return int
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
     */
    public function writeBytes(string $buf, int $num = null): int
    {
        $bufSize = CryptoUtil::safeStrlen($buf);
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
            $buf = CryptoUtil::safeSubstr($buf, $written, null);
            $this->pos += $written;
            $this->stat = \fstat($this->fp);
            $remaining -= $written;
        } while ($remaining > 0);
        return $num;
    }
}
