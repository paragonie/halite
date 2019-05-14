<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    FileAccessDenied,
    InvalidType
};

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
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
class MutableFile implements StreamInterface
{
    const ALLOWED_MODES = ['r+b', 'w+b', 'cb', 'c+b', 'wb'];
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
     * @throws InvalidType
     * @throws FileAccessDenied
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct($file)
    {
        if (\is_string($file)) {
            if (!\file_exists($file)) {
                if (!\is_writable(\dirname($file))) {
                    throw new FileAccessDenied(
                        'Could not write to directory that contains file'
                    );
                }
                \touch($file); // Make the file exist
            }
            if (!\is_readable($file)) {
                throw new FileAccessDenied(
                    'Could not open file for reading'
                );
            }
            if (!\is_writable($file)) {
                throw new FileAccessDenied(
                    'Could not open file for writing'
                );
            }
            $fp = \fopen($file, 'w+b');
            // @codeCoverageIgnoreStart
            if (!\is_resource($fp)) {
                throw new FileAccessDenied(
                    'Could not open file for reading'
                );
            }
            // @codeCoverageIgnoreEnd
            $this->fp = $fp;
            $this->closeAfter = true;
            $this->pos = 0;
            $this->stat = \fstat($this->fp);
        } elseif (\is_resource($file)) {
            /** @var array<string, string> $metadata */
            $metadata = \stream_get_meta_data($file);
            if (!\in_array($metadata['mode'], self::ALLOWED_MODES, true)) {
                throw new FileAccessDenied(
                    'Resource is in ' . $metadata['mode'] . ' mode, which is not allowed.'
                );
            }
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = \fstat($this->fp);
        } else {
            throw new InvalidType(
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
        return (int) $stat['size'];
    }

    /**
     * Get information about the stream.
     *
     * @return array
     */
    public function getStreamMetadata(): array
    {
        return \stream_get_meta_data($this->fp);
    }

    /**
     * Read from a stream; prevent partial reads
     *
     * @param int $num
     * @param bool $skipTests
     * @return string
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     */
    public function readBytes(int $num, bool $skipTests = false): string
    {
        // @codeCoverageIgnoreStart
        if ($num < 0) {
            throw new CannotPerformOperation('num < 0');
        } elseif ($num === 0) {
            return '';
        }
        if (($this->pos + $num) > $this->stat['size']) {
            throw new CannotPerformOperation('Out-of-bounds read');
        }
        // @codeCoverageIgnoreEnd
        $buf = '';
        $remaining = $num;
        do {
            if ($remaining <= 0) {
                // @codeCoverageIgnoreStart
                break;
                // @codeCoverageIgnoreEnd
            }
            /** @var int $bufSize */
            $bufSize = \min($remaining, self::CHUNK);
            /** @var string|bool $read */
            $read = \fread($this->fp, $bufSize);
            if (!\is_string($read)) {
                // @codeCoverageIgnoreStart
                throw new FileAccessDenied(
                    'Could not read from the file'
                );
                // @codeCoverageIgnoreEnd
            }
            $buf .= $read;
            $readSize = Binary::safeStrlen($read);
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
        /** @var array $stat */
        $stat = \fstat($this->fp);
        /** @var int $pos */
        $pos = \ftell($this->fp);
        return (int) (
            PHP_INT_MAX & (
                (int) $stat['size'] - $pos
            )
        );
    }
    
    /**
     * Set the current cursor position to the desired location
     * 
     * @param int $i
     * @return bool
     * @throws CannotPerformOperation
     * @codeCoverageIgnore
     */
    public function reset(int $i = 0): bool
    {
        $this->pos = $i;
        if (\fseek($this->fp, $i, SEEK_SET) === 0) {
            return true;
        }
        throw new CannotPerformOperation(
            'fseek() failed'
        );
    }

    /**
     * Write to a stream; prevent partial writes
     *
     * @param string $buf
     * @param int|null $num (number of bytes)
     * @return int
     *
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws \TypeError
     */
    public function writeBytes(string $buf, int $num = null): int
    {
        $bufSize = Binary::safeStrlen($buf);
        if (!\is_int($num) || $num > $bufSize) {
            $num = $bufSize;
        }
        // @codeCoverageIgnoreStart
        if ($num < 0) {
            throw new CannotPerformOperation('num < 0');
        }
        // @codeCoverageIgnoreEnd
        $remaining = $num;
        do {
            // @codeCoverageIgnoreStart
            if ($remaining <= 0) {
                break;
            }
            // @codeCoverageIgnoreEnd
            $written = \fwrite($this->fp, $buf, $remaining);
            if ($written === false) {
                // @codeCoverageIgnoreStart
                throw new FileAccessDenied(
                    'Could not write to the file'
                );
                // @codeCoverageIgnoreEnd
            }
            $buf = Binary::safeSubstr($buf, $written, null);
            $this->pos += $written;
            $this->stat = \fstat($this->fp);
            $remaining -= $written;
        } while ($remaining > 0);
        return $num;
    }
}
