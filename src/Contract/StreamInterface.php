<?php
namespace ParagonIE\Halite\Contract;

use ParagonIE\Halite\Alerts\FileAccessDenied;

/**
 * 
 */
interface StreamInterface
{
    /**
     * Read from a stream; prevent partial reads
     * 
     * @param int $num
     * @return string
     * @throws FileAccessDenied
     */
    public function readBytes($num);
    
    /**
     * Write to a stream; prevent partial writes
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @throws FileAccessDenied
     */
    public function writeBytes($buf, $num = null);

    /**
     * @return int
     */
    public function remainingBytes();

    /**
     * Where are we in the buffer?
     *
     * @return int
     */
    public function getPos();

    /**
     * How big is this buffer?
     *
     * @return int
     */
    public function getSize();
}