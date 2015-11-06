# HaliteAlert

**Namespace**: `\ParagonIE\Halite\Alerts`

This is the base class from which all of our custom Exception classes extend.

If you write code like this:

```php
try {
    // Do something with Halite here...
} catch (\ParagonIE\Halite\Alerts\HaliteAlert $e) {
    // Oh no!
}
```

...then you should catch every run-time exception this library will throw.