<?php
declare(strict_types=1);

/**
 * Defines a fake stream wrapper for testing ReadOnlyFile operations against a stream that doesn't support fstat.
 */
final class RemoteStream
{
    private $contents;
    private $position = 0;

    function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->contents = \file_get_contents(__DIR__ . '/tmp/' . parse_url($path, PHP_URL_HOST));
        return true;
    }

    function stream_read($count)
    {
        $return = \substr($this->contents, $this->position, $count);
        $this->position += strlen($return);
        return $return;
    }

    function stream_write($data)
    {
        return false;
    }

    function stream_tell()
    {
        return $this->position;
    }

    function stream_eof()
    {
        return $this->position >= \strlen($this->contents);
    }

    function stream_seek($offset, $whence)
    {
        switch ($whence) {
            case SEEK_SET:
                if ($offset < strlen($this->contents) && $offset >= 0) {
                    $this->position = $offset;
                    return true;
                }
                return false;

            case SEEK_CUR:
                if ($offset >= 0) {
                    $this->position += $offset;
                    return true;
                }
                return false;

            case SEEK_END:
                if (strlen($this->contents) + $offset >= 0) {
                    $this->position = strlen($this->contents) + $offset;
                    return true;
                }
                return false;

            default:
                return false;
        }
    }

    function stream_metadata($path, $option, $var)
    {
        return false;
    }

    function stream_stat()
    {
        return false;
    }

}
