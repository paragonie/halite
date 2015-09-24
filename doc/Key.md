# \ParagonIE\Halite\Key

## Constants

Flags:

```php
    const SECRET_KEY       =   1;
    const PUBLIC_KEY       =   2;
    const ENCRYPTION       =   4;
    const SIGNATURE        =   8;
    const ASYMMETRIC       =  16;
```

Shortcut flags:

```php
    const CRYPTO_SECRETBOX =  5;
    const CRYPTO_AUTH      =  9;
    const CRYPTO_BOX       = 20;
    const CRYPTO_SIGN      = 24;
```

## Methods

### Constructor

Arguments:

 * `$keyMaterial` - Raw binary string represetning the cryptographic key
 * `$public` - Set to TRUE if and only if this is a public key (asymmetric only)
 * `$signing` - Set to TRUE if and only if this is a signing/MAC key
 * `$asymmetric` - Set to TRUE if and only if this is an asymmetric key (private or public)

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

### deriveFromPassword

Arguments:

* `$password` - A user-provided password
* `$salt` - A random string, length must be equal to 
  `\Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES`
* `$type` - Flags

Example:

```php
$salt = \Sodium\hex2bin(
    '762ce4cabd543065172236de1027536ad52ec4c9133ced3766ff319f10301888'
);

$enc_secret = Key::deriveFromPassword(
    'correct horse battery staple',
    $salt,
    Key::ENCRYPTION | Key::SECRET_KEY
);
```
