<?php
declare(strict_types=1);

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Asymmetric\{
    Crypto as Asymmetric,
    EncryptionPublicKey,
    EncryptionSecretKey
};
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\HiddenString;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class AsymmetricTest extends TestCase
{
    /**
     * @covers Asymmetric::encrypt()
     */
    public function testEncrypt()
    {
        $alice = KeyFactory::generateEncryptionKeyPair();
        $bob = KeyFactory::generateEncryptionKeyPair();

        $message = Asymmetric::encrypt(
            new HiddenString('test message'),
            $alice->getSecretKey(),
            $bob->getPublicKey()
        );
        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Asymmetric::decrypt(
            $message,
            $bob->getSecretKey(),
            $alice->getPublicKey()
        );

        $this->assertSame($plain->getString(), 'test message');
    }

    /**
     * @covers Asymmetric::encryptWithAd()
     * @covers Asymmetric::decryptWithAd()
     */
    public function testEncryptWithAd()
    {
        $alice = KeyFactory::generateEncryptionKeyPair();
        $bob = KeyFactory::generateEncryptionKeyPair();

        $random = \random_bytes(32);

        $message = Asymmetric::encryptWithAd(
            new HiddenString('test message'),
            $alice->getSecretKey(),
            $bob->getPublicKey(),
            $random
        );
        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Asymmetric::decryptWithAd(
            $message,
            $bob->getSecretKey(),
            $alice->getPublicKey(),
            $random
        );
        $this->assertSame($plain->getString(), 'test message');

        try {
            Asymmetric::decrypt(
                $message,
                $bob->getSecretKey(),
                $alice->getPublicKey()
            );
            $this->fail('AD did not change MAC');
        } catch (CryptoException\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        try {
            Asymmetric::decryptWithAd(
                $message,
                $bob->getSecretKey(),
                $alice->getPublicKey(),
                'wrong'
            );
            $this->fail('AD did not change MAC');
        } catch (CryptoException\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }
    }

    /**
     * @covers Asymmetric::encrypt()
     * @covers Asymmetric::decrypt()
     */
    public function testEncryptEmpty()
    {
        $alice = KeyFactory::generateEncryptionKeyPair();
        $bob = KeyFactory::generateEncryptionKeyPair();

        $message = Asymmetric::encrypt(
            new HiddenString(''),
            $alice->getSecretKey(),
            $bob->getPublicKey()
        );

        $this->assertSame(
            \strpos($message, Halite::VERSION_PREFIX),
            0
        );

        $plain = Asymmetric::decrypt(
            $message,
            $alice->getSecretKey(),
            $bob->getPublicKey()
        );

        $this->assertSame('', $plain->getString());
    }

    /**
     * @covers Asymmetric::encrypt()
     * @covers Asymmetric::decrypt()
     */
    public function testEncryptFail()
    {
        $alice = KeyFactory::generateEncryptionKeyPair();
        $bob = KeyFactory::generateEncryptionKeyPair();
        
        $message = Asymmetric::encrypt(
            new HiddenString('test message'),
            $alice->getSecretKey(),
            $bob->getPublicKey(),
            true
        );
        $r = random_int(0, \mb_strlen($message, '8bit') - 1);
        $amt = random_int(0, 7);
        $message[$r] = \chr(\ord($message[$r]) ^ 1 << $amt);
        
        try {
            $plain = Asymmetric::decrypt(
                $message,
                $bob->getSecretKey(),
                $alice->getPublicKey(),
                true
            );
            $this->assertSame($plain, $message);
            $this->fail(
                'This should have thrown an InvalidMessage exception!'
            );
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }

    /**
     * @covers Asymmetric::seal()
     * @covers Asymmetric::unseal()
     */
    public function testSeal()
    {
        if (
            SODIUM_LIBRARY_MAJOR_VERSION < 7 ||
            (SODIUM_LIBRARY_MAJOR_VERSION == 7 && SODIUM_LIBRARY_MINOR_VERSION < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        $alice = KeyFactory::generateEncryptionKeyPair();
        $enc_secret = $alice->getSecretKey();
        $enc_public = $alice->getPublicKey();
        
        $this->assertSame(
            sodium_crypto_box_publickey_from_secretkey($enc_secret->getRawKeyMaterial()),
            $enc_public->getRawKeyMaterial()
        );
        
        $message = new HiddenString('This is for your eyes only');
        
        $kp = sodium_crypto_box_keypair();
        $test = sodium_crypto_box_seal($message->getString(), sodium_crypto_box_publickey($kp));
        $decr = sodium_crypto_box_seal_open($test, $kp);
        $this->assertTrue($decr !== false);
        
        $sealed = Asymmetric::seal(
            $message,
            new EncryptionPublicKey(
                new HiddenString(sodium_crypto_box_publickey($kp))
            )
        );
        $opened = Asymmetric::unseal(
            $sealed,
            new EncryptionSecretKey(
                new HiddenString(sodium_crypto_box_secretkey($kp))
            )
        );
        
        $this->assertSame($opened->getString(), $message->getString());
        
        $sealed = Asymmetric::seal($message, $enc_public);
        $opened = Asymmetric::unseal($sealed, $enc_secret);
        
        $this->assertSame($opened->getString(), $message->getString());
        
        $sealed_raw = Asymmetric::seal($message, $alice->getPublicKey());
        $opened_raw = Asymmetric::unseal($sealed_raw, $alice->getSecretKey());
        
        $this->assertSame($opened_raw->getString(), $message->getString());
    }

    /**
     * @covers Asymmetric::seal()
     * @covers Asymmetric::unseal()
     */
    public function testSealFail()
    {
        if (
            SODIUM_LIBRARY_MAJOR_VERSION < 7 ||
            (SODIUM_LIBRARY_MAJOR_VERSION == 7 && SODIUM_LIBRARY_MINOR_VERSION < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        
        $alice = KeyFactory::generateEncryptionKeyPair();
        
        $message = new HiddenString('This is for your eyes only');
        $sealed = Asymmetric::seal($message, $alice->getPublicKey(), true);
        
        // Let's flip one bit, randomly:
        $r = random_int(0, \mb_strlen($sealed, '8bit') - 1);
        $amt = 1 << random_int(0, 7);
        $sealed[$r] = \chr(\ord($sealed[$r]) ^ $amt);
        
        // This should throw an exception
        try {
            $opened = Asymmetric::unseal($sealed, $alice->getSecretKey());
            $this->assertSame($opened->getString(), $message);
            $this->fail(
                'This should have thrown an InvalidMessage exception!'
            );
        } catch (CryptoException\InvalidKey $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidKey);
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }

    /**
     * @covers Asymmetric::sign()
     * @covers Asymmetric::verify()
     */
    public function testSign()
    {
        $alice = KeyFactory::generateSignatureKeyPair();
        
        $message = 'test message';
        $signature = Asymmetric::sign($message, $alice->getSecretKey());
        
        $this->assertTrue(strlen($signature) === 88);
        
        $this->assertTrue(
            Asymmetric::verify($message, $alice->getPublicKey(), $signature)
        );
    }

    /**
     * @covers Asymmetric::sign()
     * @covers Asymmetric::verify()
     */
    public function testSignFail()
    {
        $alice = KeyFactory::generateSignatureKeyPair();
        
        $message = 'test message';
        $signature = Asymmetric::sign($message, $alice->getSecretKey(), true);
        
        $this->assertFalse(
            Asymmetric::verify(
                'wrongmessage',
                $alice->getPublicKey(),
                $signature,
                true
            )
        );
        
        $_signature = $signature;
        // Let's flip one bit, randomly:
        $r = random_int(0, \mb_strlen($_signature, '8bit') - 1);
        $_signature[$r] = \chr(
            \ord($_signature[$r])
                ^
            1 << random_int(0, 7)
        );
        
        $this->assertFalse(
            Asymmetric::verify(
                $message,
                $alice->getPublicKey(),
                $_signature,
                true
            )
        );
    }
}
