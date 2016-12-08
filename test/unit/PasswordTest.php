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
        $this->assertTrue(\is_string($hash));
        
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
            Password::needsRehash($legacyHash, $key);
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
            Password::needsRehash($legacyHash, $key);
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        $legacyHash = '31420201016257a21cbfbf16b0ec55cc1269a9da4654bbe343b828d27a571ea7c466' .
            '80c5c16a43e2451b7323b9b57b38577526329e5062527124aebd4818ca3cb34e14dcd40fd3aa21' .
            'dec98fcd7ce6d1ab1118f00db09725a7c97b1e88c4e2c91923a1ba5b7677d64174a3323dd3f080' .
            '04126167ebf2117a35a05d796bc26698b13b2a3e5fa3b52201692987cf2cd0487c3f3c8ac0cdd7' .
            'daa5703748ef94310671512e0254f5bbbdfe2482de1b8289d12232488fbd96a50d36673ba5633a' .
            '8efb3d35dd0721b3a64d857424dc03e6cb2922c09710fa05cf8aa496b9ea';
        $this->assertTrue(
            Password::verify(new HiddenString('test password'), $legacyHash, $key),
            'Legacy password hash calculation.'
        );

        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertFalse(Password::needsRehash($hash, $key));
    }
}
