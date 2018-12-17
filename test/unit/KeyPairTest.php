<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\{
    Alerts as CryptoException,
    EncryptionKeyPair,
    KeyFactory,
    SignatureKeyPair
};
use ParagonIE\Halite\Asymmetric\{
    Crypto as Asymmetric,
    SignatureSecretKey,
    SignaturePublicKey
};
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

final class KeyPairTest extends TestCase
{
    /**
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
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
            Asymmetric::verify(
                $message,
                $sign_public,
                $signed
            )
        );

        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
            "\x9a\xce\x92\x8f\x6a\x27\x93\x8e\x87\xac\x9b\x97\xfb\xe2\x50\x6b" .
            "\x67\xd5\x8b\x68\xeb\x37\xc2\x2d\x31\xdb\xcf\x7e\x8d\xa0\xcb\x17",
            KeyFactory::INTERACTIVE
        );
    }

    /**
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSalt
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
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
            Asymmetric::verify(
                $message,
                $sign_public,
                $signed
            )
        );
        
        $this->assertSame(
            $sign_public->getRawKeyMaterial(),
            "\x88\x9c\xc0\x7a\x90\xb8\x98\xf4\x6b\x47\xfe\xcc\x91\x42\x58\x45".
            "\x41\xcf\x4b\x5c\x6a\x82\x2d\xdc\xc6\x8b\x87\xbc\x08\x2f\xfe\x95"
        );
    }

    /**
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public function testEncryptionKeyPair()
    {
        $boxKeypair = KeyFactory::generateEncryptionKeyPair();
        $boxSecret = $boxKeypair->getSecretKey();
        $boxPublic = $boxKeypair->getPublicKey();
        $this->assertInstanceOf(\ParagonIE\Halite\Asymmetric\SecretKey::class, $boxSecret);
        $this->assertInstanceOf(\ParagonIE\Halite\Asymmetric\PublicKey::class, $boxPublic);

        $second = new EncryptionKeyPair(
            $boxPublic,
            $boxSecret
        );
        $this->assertSame(
            Hex::encode($boxSecret->getRawKeyMaterial()),
            Hex::encode($second->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($boxPublic->getRawKeyMaterial()),
            Hex::encode($second->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );

        $third = new EncryptionKeyPair(
            $boxSecret,
            $boxPublic
        );
        $this->assertSame(
            Hex::encode($boxSecret->getRawKeyMaterial()),
            Hex::encode($third->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($boxPublic->getRawKeyMaterial()),
            Hex::encode($third->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );
        $fourth = new EncryptionKeyPair(
            $boxSecret
        );
        $this->assertSame(
            Hex::encode($boxSecret->getRawKeyMaterial()),
            Hex::encode($fourth->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($boxPublic->getRawKeyMaterial()),
            Hex::encode($fourth->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );

        try {
            new EncryptionKeyPair(
                $boxSecret,
                $boxPublic,
                $boxPublic
            );
            $this->fail('More than two public keys was erroneously accepted');
        } catch (\InvalidArgumentException $ex) {
        }
        try {
            new EncryptionKeyPair(
                $boxPublic
            );
            $this->fail('Two public keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
        try {
            new EncryptionKeyPair(
                KeyFactory::generateEncryptionKey()
            );
            $this->fail('Symmetric key was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
        try {
            new EncryptionKeyPair(
                $boxSecret,
                KeyFactory::generateEncryptionKey()
            );
            $this->fail('Symmetric key was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }

        try {
            new EncryptionKeyPair(
                $boxSecret,
                $boxSecret
            );
            $this->fail('Two secret keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }

        try {
            new EncryptionKeyPair(
                $boxPublic,
                $boxPublic
            );
            $this->fail('Two public keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
    }

    /**
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public function testFileStorage()
    {
        $filename = tempnam(__DIR__.'/tmp/', 'key');
        $key = KeyFactory::generateEncryptionKeyPair();
        KeyFactory::save($key, $filename);
        
        $copy = KeyFactory::loadEncryptionKeyPair($filename);
        
        $this->assertSame(
            $key->getPublicKey()->getRawKeyMaterial(),
            $copy->getPublicKey()->getRawKeyMaterial()
        );
        unlink($filename);
    }

    /**
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     */
    public function testMutation()
    {
        $sign_kp = KeyFactory::generateSignatureKeyPair();
        $box_kp = $sign_kp->getEncryptionKeyPair();
        $sign_sk = $sign_kp->getSecretKey();
        $sign_pk = $sign_kp->getPublicKey();

        $enc_sk = $sign_sk->getEncryptionSecretKey();
        $enc_pk = $sign_pk->getEncryptionPublicKey();
        $this->assertSame(
            Hex::encode($enc_pk->getRawKeyMaterial()),
            Hex::encode($enc_sk->derivePublicKey()->getRawKeyMaterial())
        );
        $this->assertSame(
            Hex::encode($enc_sk->getRawKeyMaterial()),
            Hex::encode($box_kp->getSecretKey()->getRawKeyMaterial())
        );
    }

    /**
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidKey
     */
    public function testSignatureKeyPair()
    {
        $signKeypair = KeyFactory::generateSignatureKeyPair();
        $signSecret = $signKeypair->getSecretKey();
        $signPublic = $signKeypair->getPublicKey();
        $this->assertInstanceOf(\ParagonIE\Halite\Asymmetric\SecretKey::class, $signSecret);
        $this->assertInstanceOf(\ParagonIE\Halite\Asymmetric\PublicKey::class, $signPublic);

        $second = new SignatureKeyPair(
            $signPublic,
            $signSecret
        );
        $this->assertSame(
            Hex::encode($signSecret->getRawKeyMaterial()),
            Hex::encode($second->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($signPublic->getRawKeyMaterial()),
            Hex::encode($second->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );

        $third = new SignatureKeyPair(
            $signSecret,
            $signPublic
        );
        $this->assertSame(
            Hex::encode($signSecret->getRawKeyMaterial()),
            Hex::encode($third->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($signPublic->getRawKeyMaterial()),
            Hex::encode($third->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );
        $fourth = new SignatureKeyPair(
            $signSecret
        );
        $this->assertSame(
            Hex::encode($signSecret->getRawKeyMaterial()),
            Hex::encode($fourth->getSecretKey()->getRawKeyMaterial()),
            'Secret keys differ'
        );
        $this->assertSame(
            Hex::encode($signPublic->getRawKeyMaterial()),
            Hex::encode($fourth->getPublicKey()->getRawKeyMaterial()),
            'Public keys differ'
        );

        try {
            new SignatureKeyPair(
                $signSecret,
                $signPublic,
                $signPublic
            );
            $this->fail('More than two public keys was erroneously accepted');
        } catch (\InvalidArgumentException $ex) {
        }
        try {
            new SignatureKeyPair(
                $signPublic
            );
            $this->fail('Two public keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
        try {
            new SignatureKeyPair(
                KeyFactory::generateAuthenticationKey()
            );
            $this->fail('Symmetric key was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
        try {
            new SignatureKeyPair(
                $signSecret,
                KeyFactory::generateAuthenticationKey()
            );
            $this->fail('Symmetric key was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }

        try {
            new SignatureKeyPair(
                $signSecret,
                $signSecret
            );
            $this->fail('Two secret keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }

        try {
            new SignatureKeyPair(
                $signPublic,
                $signPublic
            );
            $this->fail('Two public keys was erroneously accepted');
        } catch (\ParagonIE\Halite\Alerts\InvalidKey $ex) {
        }
    }

    /**
     * @throws TypeError
     * @throws CryptoException\InvalidKey
     */
    public function testPublicDerivation()
    {
        $enc_kp = KeyFactory::generateEncryptionKeyPair();
        $enc_secret = $enc_kp->getSecretKey();
        $enc_public = $enc_kp->getPublicKey();
        
        $this->assertSame(
            $enc_secret->derivePublicKey()->getRawKeyMaterial(),
            $enc_public->getRawKeyMaterial()
        );
        
        $sign_kp = KeyFactory::generateSignatureKeyPair();
        $sign_secret = $sign_kp->getSecretKey();
        $sign_public = $sign_kp->getPublicKey();
        $this->assertSame(
            $sign_secret->derivePublicKey()->getRawKeyMaterial(),
            $sign_public->getRawKeyMaterial()
        );
    }
}
