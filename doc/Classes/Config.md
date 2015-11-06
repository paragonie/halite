# Config

**Namespace**: `\ParagonIE\Halite`

Encapsulates configuration in an immutable data structure.

## Methods

### `__get()`

> `public` __get(`string $key`)

Gets a configuration directive if it exists, or throws an [ConfigDirectiveNotFound](Alerts/ConfigDirectiveNotFound.md).

### `__set()`

> `public` __set()`

Returns false, does nothing. Configuration should not be altered at runtime.
