<?php
declare(strict_types=1);

use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\Password;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class PasswordTest extends TestCase
{
    public function testEncrypt()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));

        $hash = Password::hash(new HiddenString('test password'), $key);
        $this->assertTrue(\is_string($hash));

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
     * @covers Password::hash()
     */
    public function testEncryptWithAd()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));
        $aad = '{"userid":12}';

        $hash = Password::hash(
            new HiddenString('test password'),
            $key,
            \ParagonIE\Halite\KeyFactory::INTERACTIVE,
            $aad
        );
        $this->assertTrue(\is_string($hash));

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
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
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
    }

    public function testRehash()
    {
        $key = new EncryptionKey(new HiddenString(\str_repeat('A', 32)));

        try {
            // Sorry version 1, you get no love from us anymore.
            $legacyHash = 'MUIDAPHyUoOjV7zXTOF7nPRJP5KQTw_xOge4F9ytBnm_nqz-oKQ-yjxMRhrRLdM0X' .
                '4HrEop9vppxhM6GPnwws9khtStJaQvrU2M6QDjA4VraKkVLMHRkTbLyYGppCbfNYy9iaxsKHaV4' .
                'u9j5NSo3OTiRqiz8WHKLBrQ2ETMfd8iSIaHi1u7NXgT6zTvA8mwRa3a5SrWtHw8fEfVoSt47xTy' .
                'SLnKtpUTU_YoudA4vchbPh05YqexJKmV9PAEtTORzLN3eRiucIixaEJrm4T6rLRrqjMaaOCbUu8' .
                'oPyA==';
            Password::needsRehash($legacyHash, $key);
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame(
                'Invalid version tag',
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
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
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
        $this->assertFalse(Password::needsRehash($hash, $key));
    }
}
