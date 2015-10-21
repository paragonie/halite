<?php
use \ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\Asymmetric\SecretKey as SecretKey;
use \ParagonIE\Halite\Asymmetric\PublicKey as PublicKey;

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
        $alice = KeyPair::generate();
        $enc_secret = $alice->getSecretKey();
        $enc_public = $alice->getPublicKey();
        
        $this->assertEquals(
            \Sodium\crypto_box_publickey_from_secretkey($enc_secret->get()),
            $enc_public->get()
        );
        
        $message = 'This is for your eyes only';
        
        $kp = \Sodium\crypto_box_keypair();
        $test = \Sodium\crypto_box_seal($message, \Sodium\crypto_box_publickey($kp));
        $decr = \Sodium\crypto_box_seal_open($test, $kp);
        $this->assertTrue($decr !== false);
        
        $sealed = Asymmetric::seal($message, new PublicKey(\Sodium\crypto_box_publickey($kp)));
        $opened = Asymmetric::unseal($sealed, new SecretKey(\Sodium\crypto_box_secretkey($kp)));
        
        $sealed = Asymmetric::seal($message, $enc_public);
        $opened = Asymmetric::unseal($sealed, $enc_secret);
        
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
