<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Stream;

/**
 * Class WeakReadOnlyFile
 *
 * Like ReadOnlyFile, but with weaker guarantees
 *
 * @package ParagonIE\Halite\Stream
 */
class WeakReadOnlyFile extends ReadOnlyFile
{
    const ALLOWED_MODES = ['rb', 'r+b', 'wb', 'w+b', 'cb', 'c+b'];
}
