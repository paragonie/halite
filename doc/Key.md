# \ParagonIE\Halite\Key

## Constructor

Arguments:

 * $keyMaterial - Raw binary string represetning the cryptographic key
 * $public - Set to TRUE if and only if this is a public key (asymmetric only)
 * $signing - Set to TRUE if and only if this is a signing/MAC key
 * $asymmetric - Set to TRUE if and only if this is an asymmetric key (private or public)

Example:

```php
// For Symmetric::encrypt()
$enc_secret = new Key(
     str_repeat('A', 32), 
     false,
     false,
     false
);

// For Symmetric::authenticate()
$auth_secret = new Key(
     str_repeat('A', 32), 
     false,
     true,
     false
);

// For Asymmetric::encrypt(), Asymmetric::seal(), etc.
$box_secret = new Key(
     str_repeat('A', 32), 
     true,
     false,
     true
);

// For Asymmetric::sign()
$sign_secret = new Key(
     str_repeat('A', 32), 
     true,
     true,
     true
);
```

