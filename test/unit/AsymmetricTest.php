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
        echo "\n";
        if (
            \Sodium\library_version_major() < 7 ||
            (\Sodium\library_version_major() == 7 && \Sodium\library_version_minor() < 5)
        ) {
            $this->markTestSkipped("Your version of libsodium is too old");
        }
        
        list($enc_secret, $enc_public) = Key::generate(Key::CRYPTO_BOX);
        
        \var_dump(\Sodium\bin2hex($enc_secret->get()));
        \var_dump(\Sodium\bin2hex($enc_public->get()));
        
        $message = 'This is for your eyes only';
        
        \var_dump(['test' => $enc_public]);
        $sealed = Asymmetric::seal($message, $enc_public);
        
        /*
        Asymmetric::unseal(
            "7375f4094f1151640bd853cb13dbc1a0ee9e13b0287a89d34fa2f6732be9de13f88457553d768347116522d6d32c9cb353ef07aa7c83bd129b2bb5db35b28334c935b24f2639405a0604",
            $enc_secret
        );
        */
        $opened = Asymmetric::unseal($sealed, $enc_secret);
        
        $this->assertEquals($opened, $message);
        
        \var_dump(['test2' => $enc_public]);
        $sealed_raw = Asymmetric::seal($message, $enc_public, true);
        \var_dump(['test3' => $enc_public]);
        
        \var_dump([
            'message' => $message,
            'pubkey' => $enc_public,
            'sealed' => \Sodium\bin2hex($sealed_raw)
        ]);
        $opened_raw = Asymmetric::unseal($sealed_raw, $enc_secret, true);
        \var_dump([
            'message' => $opened_raw,
            'seckey' => $enc_secret
        ]);
        
        $this->assertEquals($opened_raw, $message);
    }
}
