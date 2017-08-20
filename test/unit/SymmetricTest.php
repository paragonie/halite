<?php
declare(strict_types=1);

use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Util;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class SymmetricTest extends TestCase
{
    /**
     * @covers Symmetric::authenticate()
     * @covers Symmetric::verify()
     */
    public function testAuthenticate()
    {
        $key = new AuthenticationKey(new HiddenString(\str_repeat('A', 32)));
        $message = 'test message';
        $mac = Symmetric::authenticate($message, $key);
        $this->assertTrue(
            Symmetric::verify($message, $key, $mac)
        );
    }
    
    /**
     * @covers Symmetric::authenticate()
     * @covers Symmetric::verify()
     */
    public function testAuthenticateFail()
    {
        $key = new AuthenticationKey(new HiddenString(\str_repeat('A', 32), true));
        $message = 'test message';
        $mac = Symmetric::authenticate($message, $key, true);
        
        // Test invalid message
        $this->assertFalse(
            Symmetric::verify('othermessage', $key, $mac, true)
        );
        
        $r = random_int(0, \mb_strlen($mac, '8bit') - 1);
        
        $_mac = $mac;
        $_mac[$r] = \chr(
            \ord($_mac[$r])
                ^
            1 << random_int(0, 7)
        );
        
        // Test invalid signature
        $this->assertFalse(
            Symmetric::verify(
                $message,
                $key,
                $_mac,
                true
            )
        );
    }

    /**
     * @covers Symmetric::encrypt()
     * @covers Symmetric::decrypt()
     */
    public function testEncrypt()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $message = Symmetric::encrypt(
            new HiddenString('test message'),
            $key
        );
        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Symmetric::decrypt($message, $key);
        $this->assertSame($plain->getString(), 'test message');
    }

    /**
     * @covers Symmetric::encryptWithAd()
     * @covers Symmetric::decryptWithAd()
     */
    public function testEncryptWithAd()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $message = Symmetric::encryptWithAd(
            new HiddenString('test message'),
            $key,
            'test'
        );
        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Symmetric::decryptWithAd($message, $key, 'test');
        $this->assertSame($plain->getString(), 'test message');

        try {
            Symmetric::decryptWithAd($message, $key, 'wrong');
            $this->fail('AD did not change MAC');
        } catch (CryptoException\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }
    }

    /**
     * @covers Symmetric::encrypt()
     */
    public function testEncryptEmpty()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $message = Symmetric::encrypt(new HiddenString(''), $key);
        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Symmetric::decrypt($message, $key);
        $this->assertSame($plain->getString(), '');
    }
    
    /**
     * @covers Symmetric::encrypt()
     */
    public function testRawEncrypt()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $message = Symmetric::encrypt(new HiddenString('test message'), $key, true);
        $this->assertTrue(strpos($message, Halite::HALITE_VERSION) === 0);
        
        $plain = Symmetric::decrypt($message, $key, true);
        $this->assertSame($plain->getString(), 'test message');
    }
    
    /**
     * @covers Symmetric::encrypt()
     */
    public function testEncryptFail()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $message = Symmetric::encrypt(
            new HiddenString('test message'),
            $key,
            true
        );

        $r = random_int(0, \mb_strlen($message, '8bit') - 1);
        $message[$r] = \chr(
            \ord($message[$r])
                ^
            1 << random_int(0, 7)
        );
        try {
            $plain = Symmetric::decrypt($message, $key, true);
            $this->assertSame($plain, $message);
            $this->fail(
                'This should have thrown an InvalidMessage exception!'
            );
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
    
    /**
     * @covers Symmetric::unpackMessageForDecryption()
     */
    public function testUnpack()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        
        // Randomly sized plaintext
        $size = random_int(1, 1024);
        $plaintext = \random_bytes($size);
        $message = Symmetric::encrypt(
            new HiddenString($plaintext),
            $key,
            true
        );
        
        // Let's unpack our message
        $unpacked = Symmetric::unpackMessageForDecryption($message);
        
        // Now to test our expected results!
        $this->assertSame(Util::safeStrlen($unpacked[0]), Halite::VERSION_TAG_LEN);
        $this->assertTrue($unpacked[1] instanceof \ParagonIE\Halite\Symmetric\Config);
        $config = $unpacked[1];
        if ($config instanceof \ParagonIE\Halite\Symmetric\Config) {
            $this->assertSame(Util::safeStrlen($unpacked[2]), $config->HKDF_SALT_LEN);
            $this->assertSame(Util::safeStrlen($unpacked[3]), SODIUM_CRYPTO_STREAM_NONCEBYTES);
            $this->assertSame(
                Util::safeStrlen($unpacked[4]),
                Util::safeStrlen($message) - (
                    Halite::VERSION_TAG_LEN +
                    $config->HKDF_SALT_LEN +
                    SODIUM_CRYPTO_STREAM_NONCEBYTES +
                    $config->MAC_SIZE
                )
            );
            $this->assertSame(Util::safeStrlen($unpacked[5]), $config->MAC_SIZE);
        } else {
            $this->fail('Cannot continue');
        }
    }
}