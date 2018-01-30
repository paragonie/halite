<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\{
    Base32,
    Base32Hex,
    Base64,
    Base64UrlSafe,
    Hex
};
use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\Halite;
use PHPUnit\Framework\TestCase;

final class HaliteTest extends TestCase
{
    public function testLibsodiumDetection()
    {
        $this->assertTrue(
            Halite::isLibsodiumSetupCorrectly()
        );
    }

    /**
     * @throws CryptoException\InvalidType
     * @throws Exception
     * @throws TypeError
     */
    public function testEncoding()
    {
        $random_bytes = random_bytes(31);

        // Backwards compatibility:
        $encoder = Halite::chooseEncoder(false);
        $this->assertSame(
            Hex::encode($random_bytes),
            $encoder($random_bytes)
        );
        $encoder = Halite::chooseEncoder(true);
        $this->assertSame(
            null,
            $encoder
        );

        // New encoding in version 3:
        $encoder = Halite::chooseEncoder(Halite::ENCODE_HEX);
        $this->assertSame(
            Hex::encode($random_bytes),
            $encoder($random_bytes)
        );

        $encoder = Halite::chooseEncoder(Halite::ENCODE_BASE32);
        $this->assertSame(
            Base32::encode($random_bytes),
            $encoder($random_bytes)
        );

        $encoder = Halite::chooseEncoder(Halite::ENCODE_BASE32HEX);
        $this->assertSame(
            Base32Hex::encode($random_bytes),
            $encoder($random_bytes)
        );

        $encoder = Halite::chooseEncoder(Halite::ENCODE_BASE64);
        $this->assertSame(
            Base64::encode($random_bytes),
            $encoder($random_bytes)
        );

        $encoder = Halite::chooseEncoder(Halite::ENCODE_BASE64URLSAFE);
        $this->assertSame(
            Base64UrlSafe::encode($random_bytes),
            $encoder($random_bytes)
        );

        try {
            Halite::chooseEncoder('dsfargeg');
            $this->fail('Invalid type allowed for Encoder');
        } catch (\ParagonIE\Halite\Alerts\InvalidType $ex) {
        }
    }
}
