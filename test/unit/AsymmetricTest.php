<?php
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class AsymmetricTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $alice = Asymmetric::generateKeys();
        $bob = Asymmetric::generateKeys();
        
        $message = Asymmetric::encrypt(
            'test message',
            $alice->getSecretKey(),
            $bob->getPublicKey()
        );
        
        $this->assertTrue(strpos($message, '31420006') === 0);
        
        $plain = Asymmetric::decrypt(
            $message,
            $bob->getSecretKey(),
            $alice->getPublicKey()
        );
        
        $this->assertEquals($plain, 'test message');
    }
    
    public function testEncryptFail()
    {
        
        $alice = Asymmetric::generateKeys();
        $bob = Asymmetric::generateKeys();
        
        $message = Asymmetric::encrypt(
            'test message',
            $alice->getSecretKey(),
            $bob->getPublicKey(),
            true
        );
        $r = \Sodium\randombytes_uniform(\mb_strlen($message, '8bit'));
        $amt = \Sodium\randombytes_uniform(8);
        $message[$r] = \chr(\ord($message[$r]) ^ 1 << $amt);
        
        try {
            $plain = Asymmetric::decrypt(
                $message,
                $bob->getSecretKey(),
                $alice->getPublicKey(),
                true
            );
            $this->assertEquals($plain, $message);
            throw new \Exception('ERROR: THIS SHOULD ALWAYS FAIL');
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
    
    public function testSeal()
    {
        if (
            \Sodium\library_version_major() < 7 ||
            (\Sodium\library_version_major() == 7 && \Sodium\library_version_minor() < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        $alice = KeyPair::deriveFromPassword(
            'apple',
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            Key::CRYPTO_BOX
        );
        
        $message = 'This is for your eyes only';
        
        $sealed = Asymmetric::seal($message, $alice->getPublicKey());
        
        $known_good = Asymmetric::unseal(
            "7375f4094f1151640bd853cb13dbc1a0ee9e13b0287a89d34fa2f6732be9de13f88457553d768347116522d6d32c9cb353ef07aa7c83bd129b2bb5db35b28334c935b24f2639405a0604",
            $alice->getSecretKey()
        );
        
        $opened = Asymmetric::unseal($sealed, $alice->getSecretKey());
        
        $this->assertEquals($opened, $message);
        
        $sealed_raw = Asymmetric::seal($message, $alice->getPublicKey());
        $opened_raw = Asymmetric::unseal($sealed_raw, $alice->getSecretKey());
        
        $this->assertEquals($opened_raw, $message);
    }
    
    public function testSealFail()
    {
        if (
            \Sodium\library_version_major() < 7 ||
            (\Sodium\library_version_major() == 7 && \Sodium\library_version_minor() < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        
        $alice = KeyPair::generate();
        
        $message = 'This is for your eyes only';
        $sealed = Asymmetric::seal($message, $alice->getPublicKey(), true);
        
        // Let's flip one bit, randomly:
        $r = \Sodium\randombytes_uniform(\mb_strlen($sealed, '8bit'));
        $amt = 1 << \Sodium\randombytes_uniform(8);
        $sealed[$r] = \chr(\ord($sealed[$r]) ^ $amt);
        
        // This should throw an exception
        try {
            $opened = Asymmetric::unseal($sealed, $alice->getSecretKey(), true);
            $this->assertEquals($opened, $message);
            throw new Exception('ERROR: THIS SHOULD ALWAYS FAIL');
        } catch (CryptoException\InvalidKey $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidKey);
        } catch (CryptoException\InvalidMessage $e) {
            $this->assertTrue($e instanceof CryptoException\InvalidMessage);
        }
    }
    
    public function testSign()
    {
        $alice = Asymmetric::generateKeys(Key::CRYPTO_SIGN);
        
        $message = 'test message';
        $signature = Asymmetric::sign($message, $alice->getSecretKey());
        
        $this->assertTrue(strlen($signature) === 128);
        
        $this->assertTrue(
            Asymmetric::verify($message, $alice->getPublicKey(), $signature)
        );
    }
    
    public function testSignFail()
    {
        $alice = Asymmetric::generateKeys(Key::CRYPTO_SIGN);
        
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
        $r = \Sodium\randombytes_uniform(\mb_strlen($signature, '8bit'));
        $_signature[$r] = \chr(
            \ord($_signature[$r])
                ^
            1 << \Sodium\randombytes_uniform(8)
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
