<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Contract;

use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    FileAccessDenied
};

/**
 * Interface StreamInterface
 *
 * A stream used by Halite, internally.
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Contract
 */
interface StreamInterface
{
    /**
     * Where are we in the buffer?
     *
     * @return int
     */
    public function getPos(): int;

    /**
     * How big is this buffer?
     *
     * @return int
     */
    public function getSize(): int;

    /**
     * Read from a stream; prevent partial reads
     * 
     * @param int $num
     * @param bool $skipTests
     * @return string
     * @throws FileAccessDenied
     * @throws CannotPerformOperation
     */
    public function readBytes(int $num, bool $skipTests = false): string;

    /**
     * How many bytes are left between here and the end of the stream?
     *
     * @return int
     */
    public function remainingBytes(): int;
    
    /**
     * Write to a stream; prevent partial writes
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @return int
     * @throws FileAccessDenied
     */
    public function writeBytes(string $buf, int $num = null): int;
}
