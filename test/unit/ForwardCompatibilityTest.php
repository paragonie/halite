<?php
declare(strict_types=1);

namespace unit;

use ParagonIE\Halite\Asymmetric\Crypto as AsymmetricCrypto;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use PHPUnit\Framework\TestCase;

final class ForwardCompatibilityTest extends TestCase
{
    public function testDecryptV5(): void
    {
        $encryptionKeyPairV5 = new EncryptionKeyPair(
            new EncryptionSecretKey(
                new HiddenString(\hex2bin('37d90f79b3c283d23431417483b1c97c8d745f874eef9ffe370d1acbe674162a'))
            )
        );

        $decryptionKeyPair = new EncryptionKeyPair(
            new EncryptionSecretKey(
                new HiddenString(\hex2bin('f601b26d42b3b6b387928b0e76fd5e9a62b2e64b131d2b033d01f02abd5f0fc2'))
            )
        );

        $asymmetric = 'MUIFAOOhCfwkfuthDoJ5BYIPSbD-CUN1WhuhNFcv83MU-o8UCksRNHlVfKA4mD_lopid8N7FfBKik5Qfungo-rgC201gUiR_EZ9G6ilnz7j3jV6egSv00OVs7GruP3Pb0-7bV4ye6Kru2u2J__GeVs9xFLbVLia5-UADkYPDOQ5Z';
        $symmetric = 'MUIFACctAVGUcrAmOrQksMG7zI_zPawdW521kFstnbEB43S_QR6oXvEmgZPatK2SKfzmfYacrhpbpNlfgFdev5sypPRZAuu6sFjfVezctpQfvmyZqh2D2HVCkVamRve03Zq7fcU4uMTbdIA4NClAo03RCHqnDNHnpi0wCTl8A_tf';

        $this->assertSame(
            'marko',
            AsymmetricCrypto::decrypt(
                $asymmetric,
                $decryptionKeyPair->getSecretKey(),
                $encryptionKeyPairV5->getPublicKey()
            )->getString()
        );

        $this->assertSame(
            'marko',
            SymmetricCrypto::decrypt(
                $symmetric,
                new EncryptionKey(new HiddenString(str_repeat('A', 32)))
            )->getString()
        );
    }
}
