# HiddenString

This was introduced in Halite 3.

**Namespace**: `\ParagonIE\Halite`

This class just encapsulates a string to hide its contents from stack
traces when an exception is thrown.

To use it:

```php
$string = new HiddenString('foo');

$something = $string . ' bar';
var_dump($something); // string(7) "foo bar"
```

Optionally, you can pass `true` as a second argument to make this not
usable in string concatenation:

```php
$string = new HiddenString('foo', true);

$something = $string . ' bar';
var_dump($something); // string(4) " bar"

// Explicit:
$something = $string->getString() . ' bar';
var_dump($something); // string(7) "foo bar"
```
