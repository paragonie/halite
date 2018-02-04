# ReadOnlyFile

**Namespace**: `\ParagonIE\Halite\Stream`

This represents a file that we are reading from, which should never be altered
while our cryptography operations are being performed.

## Constants

```php
    const ALLOWED_MODES = ['rb'];
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

### `getHash()`

> `public` getHash() : `string`

Returns the BLAKE2b hash of the file contents.

### `readBytes()`

> `public` readBytes(`int $num`) : `string`

Read the desired number of bytes from the internal stream, preventing partial
reads. Also performs runtime checks to prevent TOCTOU attacks (race conditions).

### `remainingBytes()`

> `public` remainingBytes() : `int`

Returns the number of bytes between the current location and the end of the 
stream.

### `reset()`

> `public` reset(`int $i = 0`)

Set the current position in the stream to the desired value.

### `toctouTest()`

> `public` toctouTest()

Verifies that the file location (`ftell($this->fp)`) has not diverged from our
current location (`$this->loc`), and that the file size has not changed.

### `writeBytes()`

> `public `writeBytes(`string $buf`, `int $num = null`)

Just returns `false`.