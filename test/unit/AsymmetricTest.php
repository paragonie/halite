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
    public function testSeal()
    {
        if (
            \Sodium\library_version_major() < 7 ||
            (\Sodium\library_version_major() == 7 && \Sodium\library_version_minor() < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        
        list($enc_secret, $enc_public) = Key::generate(Key::CRYPTO_BOX);
        
        $message = 'This is for your eyes only';
        
        $sealed = Asymmetric::seal($message, $enc_public);
        $opened = Asymmetric::unseal($sealed, $enc_secret);
        
        $this->assertEquals($opened, $message);
        
        $sealed_raw = Asymmetric::seal($message, $enc_public, true);
        $opened_raw = Asymmetric::unseal($sealed_raw, $enc_secret, true);
        $this->assertEquals($opened_raw, $message);
    }
}
