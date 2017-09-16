<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\Util as CryptoUtil;

/**
 * Class ReadOnlyFile
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Stream
 */
class ReadOnlyFile implements StreamInterface
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
     * ReadOnlyFile constructor
     *
     * @param string|resource $file
     * @param Key|null $key
     * @throws CryptoException\InvalidType
     * @throws CryptoException\FileAccessDenied
     */
    public function __construct($file, Key $key = null)
    {
        if (\is_string($file)) {
            $fp = \fopen($file, 'rb');
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
        $this->hashKey = !empty($key) 
            ? $key->getRawKeyMaterial()
            : '';
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
        $init = $this->pos;
        \fseek($this->fp, 0, SEEK_SET);

        // Create a hash context:
        $h = \sodium_crypto_generichash_init(
            $this->hashKey,
            \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
        );
        for ($i = 0; $i < $this->stat['size']; $i += self::CHUNK) {
            if (($i + self::CHUNK) > $this->stat['size']) {
                $c = \fread($this->fp, ($this->stat['size'] - $i));
            } else {
                $c = \fread($this->fp, self::CHUNK);
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
        return $this->stat['size'];
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
     * @throws CryptoException\FileAccessDenied
     * @throws CryptoException\CannotPerformOperation
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
        if (!$skipTests) {
            $this->toctouTest();
        }
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
        return (PHP_INT_MAX & ($this->stat['size'] - $this->pos));
    }

    /**
     * Set the current cursor position to the desired location
     *
     * @param int $position
     * @return bool
     * @throws CryptoException\CannotPerformOperation
     */
    public function reset(int $position = 0): bool
    {
        $this->pos = $position;
        if (\fseek($this->fp, $position, SEEK_SET) === 0) {
            return true;
        }
        throw new CryptoException\CannotPerformOperation(
            'fseek() failed'
        );
    }

    /**
     * Run-time test to prevent TOCTOU attacks (race conditions) through
     * verifying that the hash matches and the current cursor position/file
     * size matches their values when the file was first opened.
     *
     * @throws CryptoException\FileModified
     * @return void
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
    }
    
    /**
     * This is a meaningless operation for a Read-Only File!
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @return int
     * @throws CryptoException\FileAccessDenied
     */
    public function writeBytes(string $buf, int $num = null): int
    {
        unset($buf);
        unset($num);
        throw new CryptoException\FileAccessDenied(
            'This is a read-only file handle.'
        );
    }
}
