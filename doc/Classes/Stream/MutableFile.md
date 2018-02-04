# MutableFile

**Namespace**: `\ParagonIE\Halite\Stream`

This represents a file that we are writing to, and therefore is mutable.

## Constants

```php
    const ALLOWED_MODES = ['r+b', 'w+b', 'cb', 'c+b'];
    // PHP's fread() buffer is set to 8192 by default
    const CHUNK = 8192;
```

## Properties

* `$fp` (private) - File pointer
* `int $pos` (private) - Position within the stream (via `ftell()`)
* `array $stat` (private) - Statistics about the file (via `fstat()`)

## Methods

### Constructor

Arguments:

* `$file` - Either a string containing a file location or a resource (file 
  handle opened by `fopen()`)

### `readBytes()`

> `public` readBytes(`int $num`) : `string`

Read the desired number of bytes from the internal stream, preventing partial
reads.

### `reset()`

> `public` reset(`int $i = 0`)

Set the current position in the stream to the desired value.

### `writeBytes()`

> `public` writeBytes(`string $buf`, `int $num = null`) : `int`

Write `$buf` to the internal stream.
