<?php
declare(strict_types=1);

use \ParagonIE\Halite\Password;
use \ParagonIE\Halite\Symmetric\Crypto;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $key = new EncryptionKey(\str_repeat('A', 32));
        
        $hash = Password::hash('test password', $key);
        $this->assertTrue(is_string($hash));
        
        $this->assertTrue(
            Password::verify('test password', $hash, $key)
        );
        
        $this->assertFalse(
            Password::verify('wrong password', $hash, $key)
        );
    }

    public function testLegacy()
    {
        $key = new EncryptionKey(\str_repeat('A', 32));

        // This returns true based on the prefix
        $storedPassword = '31420100' . \Sodium\bin2hex(\random_bytes(179));
        $this->assertTrue(Password::needsRehash($storedPassword, $key));
        unset($storedPassword);

        $passwd = 'correct horse battery staple';
        $hash = \Sodium\crypto_pwhash_scryptsalsa208sha256_str(
            $passwd,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        $encrypted = Crypto::encrypt($hash, $key);
        $this->assertTrue(Password::needsRehash($encrypted, $key));
        $this->assertTrue(Password::verify($passwd, $encrypted, $key));
    }
}
