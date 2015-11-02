<?php
namespace ParagonIE\Halite\Contract;

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
     * @throws FileAlert\AccessDenied
     */
    public function readBytes($num);
    
    /**
     * Write to a stream; prevent partial writes
     * 
     * @param string $buf
     * @param int $num (number of bytes)
     * @throws FileAlert\AccessDenied
     */
    public function writeBytes($buf, $num = null);
}