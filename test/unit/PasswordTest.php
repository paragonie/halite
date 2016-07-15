<?php
declare(strict_types=1);

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Password;
use ParagonIE\Halite\Symmetric\EncryptionKey;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        
        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertTrue(\is_string($hash->getString()));
        
        $this->assertTrue(
            Password::verify(
                new HiddenString('test password'),
                $hash,
                $key
            )
        );
        
        $this->assertFalse(
            Password::verify(
                new HiddenString('wrong password'),
                $hash,
                $key
            )
        );
    }

    public function testRehash()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));

        try {
            // Sorry version 1, you get no love from us anymore.
            $legacyHash = '3142010064c0c42347b248372d9605621bd6e56e6ace8d2c6f6a3cf3d1a37a40' .
                '3f031b5be025f00763a92ffb47281065419663e972b1a8faa08ae34bd9fdb35b2ca7727f41' .
                'ca8edc75293d8f3bf12604ff4188d71473b605d48d1e378388465c6e4c733cae5f89802ebb' .
                '79ec6532b430a4799e545956113f116fa705e3ed2d7b17bb6dbf435f36a0f50dcb541adb82' .
                'a83f6d01ae66b2f4d46540161ba6cc37dbd0e870aed8334cb71f8162a9e7e7974396bdb1bc' .
                '4da5099423820b870e39a3ffe5';
            Password::needsRehash(new HiddenString($legacyHash), $key);
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid version tag',
                $ex->getMessage()
            );
        }

        try {
            $legacyHash = '3142020164c0c42347b248372d9605621bd6e56e6ace8d2c6f6a3cf3d1a37a40' .
                '3f031b5be025f00763a92ffb47281065419663e972b1a8faa08ae34bd9fdb35b2ca7727f41' .
                'ca8edc75293d8f3bf12604ff4188d71473b605d48d1e378388465c6e4c733cae5f89802ebb' .
                '79ec6532b430a4799e545956113f116fa705e3ed2d7b17bb6dbf435f36a0f50dcb541adb82' .
                'a83f6d01ae66b2f4d46540161ba6cc37dbd0e870aed8334cb71f8162a9e7e7974396bdb1bc' .
                '4da5099423820b870e39a3ffe5';
        Password::needsRehash(new HiddenString($legacyHash), $key);
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertFalse(Password::needsRehash($hash, $key));
    }
}
