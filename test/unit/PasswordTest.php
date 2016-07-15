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

    public function testRehash()
    {
        $key = new EncryptionKey(\str_repeat('A', 32));
        $legacyHash = '3142010064c0c42347b248372d9605621bd6e56e6ace8d2c6f6a3cf3d1a37a40' .
            '3f031b5be025f00763a92ffb47281065419663e972b1a8faa08ae34bd9fdb35b2ca7727f41' .
            'ca8edc75293d8f3bf12604ff4188d71473b605d48d1e378388465c6e4c733cae5f89802ebb' .
            '79ec6532b430a4799e545956113f116fa705e3ed2d7b17bb6dbf435f36a0f50dcb541adb82' .
            'a83f6d01ae66b2f4d46540161ba6cc37dbd0e870aed8334cb71f8162a9e7e7974396bdb1bc' .
            '4da5099423820b870e39a3ffe5';

        $this->assertTrue(Password::needsRehash($legacyHash, $key));

        $hash = Password::hash('test password', $key);
        $this->assertFalse(Password::needsRehash($hash, $key));
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
