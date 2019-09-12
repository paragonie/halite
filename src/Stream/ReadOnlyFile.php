<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    FileAccessDenied,
    FileError,
    FileModified,
    InvalidType,
};
use ParagonIE\Halite\Key;

/**
 * Class ReadOnlyFile
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
class ReadOnlyFile implements StreamInterface
{
    const ALLOWED_MODES = ['rb'];
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
     * @var string
     */
    private $hash;

    /**
     * @var int
     */
    private $pos = 0;

    /**
     * @var null|string
     */
    private $hashKey = null;

    /**
     * @var array
     */
    private $stat = [];

    /**
     * ReadOnlyFile constructor.
     *
     * @param string|resource $file
     * @param Key|null $key
     *
     * @throws FileAccessDenied
     * @throws FileError
     * @throws InvalidType
     * @throws \TypeError
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct($file, Key $key = null)
    {
        if (\is_string($file)) {
            if (!\is_readable($file)) {
                throw new FileAccessDenied(
                    'Could not open file for reading'
                );
            }
            /** @var resource|bool $fp */
            $fp = \fopen($file, 'rb');
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
            $this->stat = $this->fstat();
        } elseif (\is_resource($file)) {
            /** @var array<string, string> $metadata */
            $metadata = \stream_get_meta_data($file);
            if (!\in_array($metadata['mode'], (array) static::ALLOWED_MODES, true)) {
                throw new FileAccessDenied(
                    'Resource is in ' . $metadata['mode'] . ' mode, which is not allowed.'
                );
            }
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = $this->fstat();
        } else {
            throw new InvalidType(
                'Argument 1: Expected a filename or resource'
            );
        }
        // @codeCoverageIgnoreStart
        $this->hashKey = !empty($key)
            ? $key->getRawKeyMaterial()
            : '';
        // @codeCoverageIgnoreEnd
        $this->hash = $this->getHash();
    }

    /**
     * Make sure we invoke $this->close()
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * Close the file handle.
     * @return void
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
     * Calculate a BLAKE2b hash of a file
     *
     * @return string
     */
    public function getHash(): string
    {
        if ($this->hash) {
            $this->toctouTest();
            return $this->hash;
        }
        $init = $this->pos;
        \fseek($this->fp, 0, SEEK_SET);

        // Create a hash context:
        $h = \sodium_crypto_generichash_init(
            $this->hashKey,
            \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        );
        for ($i = 0; $i < $this->stat['size']; $i += self::CHUNK) {
            if (($i + self::CHUNK) > $this->stat['size']) {
                $c = \fread($this->fp, ((int) $this->stat['size'] - $i));
            } else {
                $c = \fread($this->fp, self::CHUNK);
            }
            if (!\is_string($c)) {
                // @codeCoverageIgnoreStart
                throw new FileError('Could not read file');
                // @codeCoverageIgnoreEnd
            }
            \sodium_crypto_generichash_update($h, $c);
        }
        // Reset the file pointer's internal cursor to where it was:
        \fseek($this->fp, $init, SEEK_SET);
        return \sodium_crypto_generichash_final($h);
    }

    /**
     * Where are we in the buffer?
     *
     * @return int
     */
    public function getPos(): int
    {
        return $this->pos;
    }

    /**
     * How big is this buffer?
     *
     * @return int
     */
    public function getSize(): int
    {
        return (int) $this->stat['size'];
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
     * Read from a stream; prevent partial reads (also uses run-time testing to
     * prevent partial reads -- you can turn this off if you need performance
     * and aren't concerned about race condition attacks, but this isn't a
     * decision to make lightly!)
     *
     * @param int $num
     * @param bool $skipTests Only set this to TRUE if you're absolutely sure
     *                           that you don't want to defend against TOCTOU /
     *                           race condition attacks on the filesystem!
     * @return string
     * @throws CannotPerformOperation
     * @throws FileAccessDenied
     * @throws FileModified
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
        $buf = '';
        // @codeCoverageIgnoreEnd
        $remaining = $num;
        if (!$skipTests) {
            $this->toctouTest();
        }
        do {
            // @codeCoverageIgnoreStart
            if ($remaining <= 0) {
                break;
            }
            // @codeCoverageIgnoreEnd
            /** @var string|bool $read */
            $read = \fread($this->fp, $remaining);
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
        return (int) (
            PHP_INT_MAX & (
                (int) $this->stat['size'] - $this->pos
            )
        );
    }

    /**
     * Set the current cursor position to the desired location
     *
     * @param int $position
     * @return bool
     * @throws CannotPerformOperation
     */
    public function reset(int $position = 0): bool
    {
        $this->pos = $position;
        if (\fseek($this->fp, $position, SEEK_SET) === 0) {
            return true;
        }
        // @codeCoverageIgnoreStart
        throw new CannotPerformOperation(
            'fseek() failed'
        );
        // @codeCoverageIgnoreEnd
    }

    /**
     * Run-time test to prevent TOCTOU attacks (race conditions) through
     * verifying that the hash matches and the current cursor position/file
     * size matches their values when the file was first opened.
     *
     * @throws FileModified
     * @return void
     */
    public function toctouTest()
    {
        if (\ftell($this->fp) !== $this->pos) {
            // @codeCoverageIgnoreStart
            throw new FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
            // @codeCoverageIgnoreEnd
        }
        $stat = $this->fstat();
        if ($stat['size'] !== $this->stat['size']) {
            throw new FileModified(
                'Read-only file has been modified since it was opened for reading'
            );
        }
    }

    /**
     * This is a meaningless operation for a Read-Only File!
     *
     * @param string $buf
     * @param int $num (number of bytes)
     * @return int
     * @throws FileAccessDenied
     */
    public function writeBytes(string $buf, int $num = null): int
    {
        unset($buf);
        unset($num);
        throw new FileAccessDenied(
            'This is a read-only file handle.'
        );
    }

    /**
     * Wraps fstat to allow calculation of file-size on stream wrappers.
     *
     * @return array
     */
    private function fstat() : array {
      $stat = \fstat($this->fp);
      if ($stat) {
        return $stat;
      }
      // The resource is remote or a stream wrapper like php://input
      $stat = [
        'size' => 0,
      ];
      \fseek($this->fp, 0);
      while (!feof($this->fp)) {
        $stat['size'] += \strlen(\fread($this->fp, 8192));
      }
      \fseek($this->fp, $this->pos);
      return $stat;
    }
}
