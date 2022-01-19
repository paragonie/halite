<?php
declare(strict_types=1);

use ParagonIE\Halite\Password;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

final class PasswordTest extends TestCase
{
    /**
     * @throws InvalidMessage
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     */
    public function testEncrypt()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not installed');
        }
        $key = new EncryptionKey(new HiddenString(str_repeat('A', 32)));

        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertTrue(is_string($hash));

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

    /**
     * @throws Exception
     * @throws InvalidMessage
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     */
    public function testEncryptWithAd()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not installed');
        }
        $key = new EncryptionKey(new HiddenString(str_repeat('A', 32)));
        $aad = '{"userid":12}';

        $hash = Password::hash(
            new HiddenString('test password'),
            $key,
            KeyFactory::INTERACTIVE,
            $aad
        );
        $this->assertTrue(is_string($hash));

        $this->assertTrue(
            Password::verify(
                new HiddenString('test password'),
                $hash,
                $key,
                $aad
            )
        );
        try {
            Password::verify(
                new HiddenString('test password'),
                $hash,
                $key
            );
            $this->fail('AD did not change MAC');
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        $this->assertFalse(
            Password::verify(
                new HiddenString('wrong password'),
                $hash,
                $key,
                $aad
            )
        );

        $passwd = new HiddenString('test' . random_bytes(32));
        try {
            $hash = 'MUIEA';
            Password::verify($passwd, $hash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is way too short.',
                $ex->getMessage()
            );
        }
        try {
            $hash = 'MUIEAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0XoPyB==';
            Password::verify($passwd, $hash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is too short.',
                $ex->getMessage()
            );
        }
    }

    /**
     * @throws InvalidMessage
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     */
    public function testKeyLevels()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not installed');
        }
        $key = new EncryptionKey(new HiddenString(str_repeat('A', 32)));
        $aad = '{"userid":12}';

        $passwd = new HiddenString('test password');
        foreach ([KeyFactory::INTERACTIVE, KeyFactory::MODERATE, KeyFactory::SENSITIVE] as $level) {
            $hash = Password::hash($passwd, $key, $level, $aad);
            $this->assertTrue(is_string($hash));
            $this->assertFalse(Password::needsRehash($hash, $key, $level, $aad));
            $this->assertTrue(Password::verify($passwd, $hash, $key, $aad));
        }
    }

    /**
     * @throws InvalidMessage
     * @throws TypeError
     * @throws CryptoException\CannotPerformOperation
     * @throws CryptoException\InvalidDigestLength
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\InvalidType
     */
    public function testRehash()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not installed');
        }
        $key = new EncryptionKey(new HiddenString(str_repeat('A', 32)));

        try {
            // Sorry version 1, you get no love from us anymore.
            $legacyHash = 'MUIEAM8F9xoJSz0yBWtA8_DWq0tJM7RuTYPxehbgJ-CW0e-TnJz3-TrZI1ID8gujH' .
                '5pQNzejQZEeMwaWlbIgHbpz0OUrITw5Urlv-_RxI4Ih-80uXieWfq0cOp9QqnX9uCO56OsczuPL' .
                '5nDCUcTfnG-GnfvH6FkINGBLMkWfzUzaEBNS1zJVcszqle5GEAp6rm9S-BwnCmbKgdigq2rw-Lu' .
                'N_lfcC4Gijx88EwW4D7L7B3r4zyVh4eFjsaU6Djqv5XIxKvH1gJPUToE_Hukd-5dV4wOI9PKtUL' .
                'ZG0w==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Invalid version tag',
                $ex->getMessage()
            );
        }
        try {
            $legacyHash = 'MUIEAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
                'oPyB==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is too short.',
                $ex->getMessage()
            );
        }
        try {
            $legacyHash = 'MUIFAPH';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is way too short.',
                $ex->getMessage()
            );
        }

        try {
            $legacyHash = 'MUIFAM8F9xoJSz0yBWtA8_DWq0tJM7RuTYPxehbgJ-CW0e-TnJz3-TrZI1ID8gujH' .
                '5pQNzejQZEeMwaWlbIgHbpz0OUrITw5Urlv-_RxI4Ih-80uXieWfq0cOp9QqnX9uCO56OsczuPL' .
                '5nDCUcTfnG-GnfvH6FkINGBLMkWfzUzaEBNS1zJVcszqle5GEAp6rm9S-BwnCmbKgdigq2rw-Lu' .
                'N_lfcC4Gijx88EwW4D7L7B3r4zyVh4eFjsaU6Djqv5XIxKvH1gJPUToE_Hukd-5dV4wOI9PKtUL' .
                'ZG0w==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertFalse(
            Password::needsRehash($hash, $key),
            'Failure: Password always needs a rehash'
        );
        $this->assertTrue(
            Password::needsRehash($hash, $key, KeyFactory::SENSITIVE)
        );
        $this->assertTrue(
            Password::needsRehash($hash, $key, 'anything')
        );
    }
}
