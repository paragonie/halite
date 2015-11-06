# CannotCloneKey extends [HaliteAlert](HaliteAlert.md)

**Namespace**: `\ParagonIE\Halite\Alerts`

All key objects should never permit this usage:

```php
$key = KeyFactory::generateEncryptionKey();
$cloned = clone $key;
```

If you attempt to do this, it will throw this exception.