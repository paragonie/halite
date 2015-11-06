# CannotSerializeKey extends [HaliteAlert](HaliteAlert.md)

**Namespace**: `\ParagonIE\Halite\Alerts`

All key objects should never permit this usage:

```php
$key = KeyFactory::generateEncryptionKey();
$store = serialize($key);
```

If you attempt to do this, it will throw this exception.

Instead, use `KeyFactory::save($key, '/path/to/file');` for persistent storage.