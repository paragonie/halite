# Halite

**Namespace**: `\ParagonIE\Halite`

This is just an abstract class that contains some constants for the current
release of Halite.

## Constants

    const VERSION              = '3.0.0';
    
    const HALITE_VERSION_KEYS  = "\x31\x40\x03\x00";
    const HALITE_VERSION_FILE  = "\x31\x41\x03\x00";
    const HALITE_VERSION       = "\x31\x42\x03\x00";
    
    const VERSION_TAG_LEN      = 4;
    const VERSION_PREFIX       = 'MUIDA';
    
    const ENCODE_HEX           = 'hex';
    const ENCODE_BASE32        = 'base32';
    const ENCODE_BASE32HEX     = 'base32hex';
    const ENCODE_BASE64        = 'base64';
    const ENCODE_BASE64URLSAFE = 'base64urlsafe';

## Static Methods

### chooseEncoder()

> `public static` chooseEncoder(`$chosen`, `bool $decode = false`)

Used to determine which encoder to select. Internal method.

### isLibsodiumSetupCorrectly()

> `public static` function isLibsodiumSetupCorrectly(`bool $echo = false`)

Returns `TRUE` if libsodium is set up correctly. `FALSE` otherwise.

Optionally, you may pass `true` to get verbose output on why it fails.
