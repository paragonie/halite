# \ParagonIE\Halite\Config

Encapsulates configuration in an immutable data structure.

## Methods

### `public` __get(`string $key`)

Gets a configuration directive if it exists, or throws an [ConfigDirectiveNotFound](Alerts/ConfigDirectiveNotFound.md).

### `public` __set()`

Returns false, does nothing. Configuration should not be altered at runtime.
