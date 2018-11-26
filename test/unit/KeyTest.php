<?php
declare(strict_types=1);

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class KeyTest extends TestCase
{
    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testDerive()
    {
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::INTERACTIVE
        );
        $this->assertSame(
            $key->getRawKeyMaterial(),
            "\x3a\x16\x68\xc1\x45\x8a\x4f\x59\x9c\x36\x4e\xa4\x7f\xae\xfa\xe1" .
            "\xee\xa3\xa6\xd0\x34\x26\x35\xc9\xb4\x79\xee\xab\xf4\x71\x86\xaa"
        );
        $salt = sodium_hex2bin(
            '762ce4cabd543065172236de1027536a'
        );

        // Issue #10
        $enc_secret = KeyFactory::deriveEncryptionKey(
            new HiddenString('correct horse battery staple'),
            $salt
        );
        $this->assertTrue(
            $enc_secret->isEncryptionKey()
        );

        $key = KeyFactory::deriveAuthenticationKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::INTERACTIVE
        );
        $this->assertSame(
            $key->getRawKeyMaterial(),
            "\x3a\x16\x68\xc1\x45\x8a\x4f\x59\x9c\x36\x4e\xa4\x7f\xae\xfa\xe1" .
            "\xee\xa3\xa6\xd0\x34\x26\x35\xc9\xb4\x79\xee\xab\xf4\x71\x86\xaa"
        );
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testDeriveOldArgon2i()
    {
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        );
        $this->assertSame(
            $key->getRawKeyMaterial(),
            "\x79\x12\x36\xc1\xf0\x6b\x73\xbd\xaa\x88\x89\x80\xe3\x2c\x4b\xdb".
            "\x25\xd1\xf9\x39\xe5\xf7\x13\x30\x5c\xd8\x4c\x50\x22\xcc\x96\x6e"
        );
        $salt = sodium_hex2bin(
            '762ce4cabd543065172236de1027536a'
        );

        // Issue #10
        $enc_secret = KeyFactory::deriveEncryptionKey(
            new HiddenString('correct horse battery staple'),
            $salt
        );
        $this->assertTrue(
            $enc_secret->isEncryptionKey()
        );
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     * @throws CryptoException\InvalidSignature
     */
    public function testDeriveSigningKey()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        );
        $sign_secret = $keypair->getSecretKey();
        $sign_public = $keypair->getPublicKey();

        $this->assertTrue($sign_secret instanceof SignatureSecretKey);
        $this->assertTrue($sign_public instanceof SignaturePublicKey);

        // Can this be used?
        $message = 'This is a test message';
        $signed = Asymmetric::sign(
            $message,
            $sign_secret
        );
        $this->assertTrue(
            Asymmetric::verify($message, $sign_public, $signed)
        );

        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
            "\x9a\xce\x92\x8f\x6a\x27\x93\x8e\x87\xac\x9b\x97\xfb\xe2\x50\x6b" .
            "\x67\xd5\x8b\x68\xeb\x37\xc2\x2d\x31\xdb\xcf\x7e\x8d\xa0\xcb\x17"
        );
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     * @throws CryptoException\InvalidSignature
     */
    public function testDeriveSigningKeyOldArgon2i()
    {
        $keypair = KeyFactory::deriveSignatureKeyPair(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        );
        $sign_secret = $keypair->getSecretKey();
        $sign_public = $keypair->getPublicKey();

        $this->assertTrue($sign_secret instanceof SignatureSecretKey);
        $this->assertTrue($sign_public instanceof SignaturePublicKey);

        // Can this be used?        
        $message = 'This is a test message';
        $signed = Asymmetric::sign(
            $message,
            $sign_secret
        );
        $this->assertTrue(
            Asymmetric::verify($message, $sign_public, $signed)
        );

        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
            "\x88\x9c\xc0\x7a\x90\xb8\x98\xf4\x6b\x47\xfe\xcc\x91\x42\x58\x45".
            "\x41\xcf\x4b\x5c\x6a\x82\x2d\xdc\xc6\x8b\x87\xbc\x08\x2f\xfe\x95"
        );
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public function testImport()
    {
        $key = KeyFactory::generateAuthenticationKey();
        $export = KeyFactory::export($key);
        $import = KeyFactory::importAuthenticationKey($export);

        $this->assertSame(
            bin2hex($key->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        $key = KeyFactory::generateEncryptionKey();
        $export = KeyFactory::export($key);
        $import = KeyFactory::importEncryptionKey($export);

        $this->assertSame(
            bin2hex($key->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        $signKeypair = KeyFactory::generateSignatureKeyPair();

        $export = KeyFactory::export($signKeypair);
        $import = KeyFactory::importSignatureKeyPair($export);
        $this->assertSame(
            bin2hex($signKeypair->getSecretKey()->getRawKeyMaterial()),
            bin2hex($import->getSecretKey()->getRawKeyMaterial())
        );
        $this->assertSame(
            bin2hex($signKeypair->getPublicKey()->getRawKeyMaterial()),
            bin2hex($import->getPublicKey()->getRawKeyMaterial())
        );

        $export = KeyFactory::export($signKeypair->getSecretKey());
        $import = KeyFactory::importSignatureSecretKey($export);
        $this->assertSame(
            bin2hex($signKeypair->getSecretKey()->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        $export = KeyFactory::export($signKeypair->getPublicKey());
        $import = KeyFactory::importSignaturePublicKey($export);
        $this->assertSame(
            bin2hex($signKeypair->getPublicKey()->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        $encKeypair = KeyFactory::generateEncryptionKeyPair();

        $export = KeyFactory::export($encKeypair);
        $import = KeyFactory::importEncryptionKeyPair($export);
        $this->assertSame(
            bin2hex($encKeypair->getSecretKey()->getRawKeyMaterial()),
            bin2hex($import->getSecretKey()->getRawKeyMaterial())
        );
        $this->assertSame(
            bin2hex($encKeypair->getPublicKey()->getRawKeyMaterial()),
            bin2hex($import->getPublicKey()->getRawKeyMaterial())
        );

        $export = KeyFactory::export($encKeypair->getSecretKey());
        $import = KeyFactory::importEncryptionSecretKey($export);
        $this->assertSame(
            bin2hex($encKeypair->getSecretKey()->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        $export = KeyFactory::export($encKeypair->getPublicKey());
        $import = KeyFactory::importEncryptionPublicKey($export);
        $this->assertSame(
            bin2hex($encKeypair->getPublicKey()->getRawKeyMaterial()),
            bin2hex($import->getRawKeyMaterial())
        );

        try {
            KeyFactory::export(new stdClass());
            $this->fail('Expected a TypeError to be raised');
        } catch (TypeError $ex) {
        }
    }

    /**
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public function testKeyTypes()
    {
        $key = KeyFactory::generateAuthenticationKey();
            $this->assertFalse($key->isAsymmetricKey());
            $this->assertFalse($key->isEncryptionKey());
            $this->assertTrue($key->isSecretKey());
            $this->assertTrue($key->isSigningKey());
            $this->assertFalse($key->isPublicKey());
        
        $key = KeyFactory::generateEncryptionKey();
            $this->assertFalse($key->isAsymmetricKey());
            $this->assertTrue($key->isEncryptionKey());
            $this->assertTrue($key->isSecretKey());
            $this->assertFalse($key->isSigningKey());
            $this->assertFalse($key->isPublicKey());
        
        $keypair = KeyFactory::generateEncryptionKeyPair();
            $enc_secret = $keypair->getSecretKey();
            $enc_public = $keypair->getPublicKey();
            $this->assertTrue($enc_secret->isAsymmetricKey());
            $this->assertTrue($enc_secret->isEncryptionKey());
            $this->assertTrue($enc_secret->isSecretKey());
            $this->assertFalse($enc_secret->isSigningKey());
            $this->assertFalse($enc_secret->isPublicKey());
            
            $this->assertTrue($enc_public->isAsymmetricKey());
            $this->assertTrue($enc_public->isEncryptionKey());
            $this->assertFalse($enc_public->isSecretKey());
            $this->assertFalse($enc_public->isSigningKey());
            $this->assertTrue($enc_public->isPublicKey());
            
        $keypair = KeyFactory::generateSignatureKeyPair();
            $sign_secret = $keypair->getSecretKey();
            $sign_public = $keypair->getPublicKey();
            $this->assertTrue($sign_secret->isAsymmetricKey());
            $this->assertFalse($sign_secret->isEncryptionKey());
            $this->assertTrue($sign_secret->isSecretKey());
            $this->assertTrue($sign_public->isSigningKey());
            $this->assertFalse($sign_secret->isPublicKey());
            
            $this->assertTrue($sign_public->isAsymmetricKey());
            $this->assertFalse($sign_public->isEncryptionKey());
            $this->assertFalse($sign_public->isSecretKey());
            $this->assertTrue($sign_public->isSigningKey());
            $this->assertTrue($sign_public->isPublicKey());
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testEncKeyStorage()
    {
        $enc_keypair = KeyFactory::deriveEncryptionKeyPair(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        );
        $enc_secret = $enc_keypair->getSecretKey();
        $enc_public = $enc_keypair->getPublicKey();
        
        $file_secret = \tempnam(__DIR__.'/tmp', 'key');
        $file_public = \tempnam(__DIR__.'/tmp', 'key');
        
        $this->assertTrue(
            KeyFactory::save($enc_secret, $file_secret) !== false
        );
        $this->assertTrue(
            KeyFactory::save($enc_public, $file_public) !== false
        );
        
        $load_public = KeyFactory::loadEncryptionPublicKey($file_public);
        $this->assertTrue(
            $load_public instanceof EncryptionPublicKey
        );
        $this->assertTrue(
            \hash_equals($enc_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );

        $encoded = KeyFactory::export($enc_secret);
        $imported = KeyFactory::importEncryptionSecretKey($encoded);

        $this->assertSame(
            $enc_secret->getRawKeyMaterial(),
            $imported->getRawKeyMaterial()
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testSignKeyStorage()
    {
        $sign_keypair = KeyFactory::deriveSignatureKeyPair(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        );
        $sign_secret = $sign_keypair->getSecretKey();
        $sign_public = $sign_keypair->getPublicKey();
        
        $file_secret = \tempnam(__DIR__.'/tmp', 'key');
        $file_public = \tempnam(__DIR__.'/tmp', 'key');
        
        $this->assertTrue(
            KeyFactory::save($sign_secret, $file_secret) !== false
        );
        $this->assertTrue(
            KeyFactory::save($sign_public, $file_public) !== false
        );
        
        $load_public = KeyFactory::loadSignaturePublicKey($file_public);
        $this->assertTrue(
            $load_public instanceof SignaturePublicKey
        );
        $this->assertTrue(
            \hash_equals($sign_public->getRawKeyMaterial(), $load_public->getRawKeyMaterial())
        );

        $encoded = KeyFactory::export($sign_secret);
        $imported = KeyFactory::importSignatureSecretKey($encoded);

        $this->assertSame(
            $sign_secret->getRawKeyMaterial(),
            $imported->getRawKeyMaterial()
        );
        
        \unlink($file_secret);
        \unlink($file_public);
    }

    /**
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testInvalidKeyLevels()
    {
        try {
            KeyFactory::deriveEncryptionKey(
                new HiddenString('apple'),
                "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                'INVALID SECURITY LEVEL IDENTIFIER SHOULD HAVE USED A CONSTANT INSTEAD'
            );
            $this->fail('Argon2 should fail on invalid');
        } catch (InvalidType $ex) {
            $this->assertSame(
                'Invalid security level for Argon2i',
                $ex->getMessage()
            );
        }
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testKeyLevels()
    {
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::MODERATE
        );
        $this->assertSame(
            'b5b21bb729b14cecca8e9d8e5811a09f0b4cb3fd4271ebf6f416ec855b6cd286',
            sodium_bin2hex($key->getRawKeyMaterial())
        );

        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::SENSITIVE
        );
        $this->assertSame(
            'd2d76bb8f27dadcc2820515dee41e2e3946f489e5e0635c987815c06c3baee95',
            sodium_bin2hex($key->getRawKeyMaterial())
        );
    }

    /**
     * @throws InvalidType
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     */
    public function testKeyLevelsOldArgon2i()
    {
        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        );
        $this->assertSame(
            '227817a188e55a679ddc8b1ca51f7aba4d1086f0512f9e3eb547c2392d49bde9',
            sodium_bin2hex($key->getRawKeyMaterial())
        );

        $key = KeyFactory::deriveEncryptionKey(
            new HiddenString('apple'),
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyFactory::SENSITIVE
        );
        $this->assertSame(
            'd2d76bb8f27dadcc2820515dee41e2e3946f489e5e0635c987815c06c3baee95',
            sodium_bin2hex($key->getRawKeyMaterial())

        );
    }

    /**
     * @throws TypeError
     */
    public function testInvalidSizes()
    {
        try {
            new \ParagonIE\Halite\Symmetric\AuthenticationKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Authentication key must be CRYPTO_AUTH_KEYBYTES bytes long', $ex->getMessage());
        }
        try {
            new \ParagonIE\Halite\Symmetric\EncryptionKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Encryption key must be CRYPTO_STREAM_KEYBYTES bytes long', $ex->getMessage());
        }
        try {
            new \ParagonIE\Halite\Asymmetric\EncryptionSecretKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Encryption secret key must be CRYPTO_BOX_SECRETKEYBYTES bytes long', $ex->getMessage());
        }
        try {
            new \ParagonIE\Halite\Asymmetric\EncryptionPublicKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Encryption public key must be CRYPTO_BOX_PUBLICKEYBYTES bytes long', $ex->getMessage());
        }
        try {
            new \ParagonIE\Halite\Asymmetric\SignatureSecretKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Signature secret key must be CRYPTO_SIGN_SECRETKEYBYTES bytes long', $ex->getMessage());
        }
        try {
            new \ParagonIE\Halite\Asymmetric\SignaturePublicKey(new HiddenString(''));
            $this->fail('Invalid key size accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
            $this->assertSame('Signature public key must be CRYPTO_SIGN_PUBLICKEYBYTES bytes long', $ex->getMessage());
        }
    }
}
