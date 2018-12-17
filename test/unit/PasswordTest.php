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
        $key = new EncryptionKey(new HiddenString(str_repeat('A', 32)));

        try {
            // Sorry version 1, you get no love from us anymore.
            $legacyHash = 'MUIDAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
                '4HrEop9vppxhM6GPnwws9khtStJaQvrU2M6QDjA4VraKkVLMHRkTbLyYGppCbfNYy9iaxsKHaV4' .
                'u9j5NSo3OTiRqiz8WHKLBrQ2ETMfd8iSIaHi1u7NXgT6zTvA8mwRa3a5SrWtHw8fEfVoSt47xTy' .
                'SLnKtpUTU_YoudA4vchbPh05YqexJKmV9PAEtTORzLN3eRiucIixaEJrm4T6rLRrqjMaaOCbUu8' .
                'oPyA==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Invalid version tag',
                $ex->getMessage()
            );
        }
        try {
            $legacyHash = 'MUIDAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
                'oPyB==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is too short.',
                $ex->getMessage()
            );
        }
        try {
            $legacyHash = 'MUIEAPH';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Encrypted password hash is way too short.',
                $ex->getMessage()
            );
        }

        try {
            $legacyHash = 'MUIDAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
                '4HrEop9vppxhM6GPnwws9khtStJaQvrU2M6QDjA4VraKkVLMHRkTbLyYGppCbfNYy9iaxsKHaV4' .
                'u9j5NSo3OTiRqiz8WHKLBrQ2ETMfd8iSIaHi1u7NXgT6zTvA8mwRa3a5SrWtHw8fEfVoSt47xTy' .
                'SLnKtpUTU_YoudA4vchbPh05YqexJKmV9PAEtTORzLN3eRiucIixaEJrm4T6rLRrqjMaaOCbUu8' .
                'oPyB==';
            Password::needsRehash($legacyHash, $key);
        } catch (InvalidMessage $ex) {
            $this->assertSame(
                'Invalid message authentication code',
                $ex->getMessage()
            );
        }

        $legacyHash = 'MUIDAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
            '4HrEop9vppxhM6GPnwws9khtStJaQvrU2M6QDjA4VraKkVLMHRkTbLyYGppCbfNYy9iaxsKHaV4' .
            'u9j5NSo3OTiRqiz8WHKLBrQ2ETMfd8iSIaHi1u7NXgT6zTvA8mwRa3a5SrWtHw8fEfVoSt47xTy' .
            'SLnKtpUTU_YoudA4vchbPh05YqexJKmV9PAEtTORzLN3eRiucIixaEJrm4T6rLRrqjMaaOCbUu8' .
            'oPyA==';
        $this->assertTrue(
            Password::verify(new HiddenString('test'), $legacyHash, $key),
            'Legacy password hash calculation.'
        );

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
