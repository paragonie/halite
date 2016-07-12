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
}
