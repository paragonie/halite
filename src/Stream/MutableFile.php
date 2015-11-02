<?php
namespace ParagonIE\Halite\Stream;

use \ParagonIE\Halite\Contract\StreamInterface;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util;

class MutableFile implements StreamInterface
{
    const CHUNK = 8192; // PHP's fread() buffer is set to 8192 by default
    
    private $fp;
    private $pos;
    private $stat = [];
    
    public function __construct($file)
    {
        if (is_string($file)) {
            $this->fp = \fopen($file, 'wb');
            $this->pos = 0;
            $this->stat = \fstat($this->fp);
        } elseif (is_resource($file)) {
            $this->fp = $file;
            $this->pos = \ftell($this->fp);
            $this->stat = \fstat($this->fp);
        }
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
            \var_dump($remaining);
        } while ($remaining > 0);
        return $buf;
    }
    
    /**
     * Write to a stream; prevent partial writes
     * 
     * @param resource $stream
     * @param string $buf
     * @param int $num (number of bytes)
     * @throws FileAlert\AccessDenied
     */
    public function writeBytes($buf, $num = null)
    {
        $bufSize = Util::safeStrlen($buf);
        if ($num === null || $num > $bufSize) {
            $num = $bufSize;
        }
        if ($num < 0) {
            throw new \Exception('num < 0');
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
    
    public function reset($i = 0)
    {
        $this->pos = $i;
        \fseek($this->fp, $i, SEEK_SET);
    }
}
