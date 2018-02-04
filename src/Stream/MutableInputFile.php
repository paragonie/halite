<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

/**
 * Class MutableInputFile
 *
 * Like ReadOnlyFile, but with weaker guarantees
 *
 * @package ParagonIE\Halite\Stream
 */
class MutableInputFile extends ReadOnlyFile
{
    const ALLOWED_MODES = ['rb', 'r+b', 'wb', 'w+b', 'cb', 'c+b'];
}
