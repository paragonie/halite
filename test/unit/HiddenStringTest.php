<?php
declare(strict_types=1);

use ParagonIE\Halite\Alerts as CryptoException;
use ParagonIE\Halite\HiddenString;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

final class HiddenStringTest extends TestCase
{
    /**
     * @throws Exception
     * @throws TypeError
     */
    public function testEquals()
    {
        $A = new HiddenString(Base64UrlSafe::encode(random_bytes(32)));
        $B = new HiddenString(Base64UrlSafe::encode(random_bytes(32)));
        $C = new HiddenString($A->getString());
        $D = new HiddenString($B->getString());

        $this->assertFalse($A->equals($B));
        $this->assertTrue($A->equals($C));
        $this->assertFalse($A->equals($D));
        $this->assertFalse($B->equals($A));
        $this->assertFalse($B->equals($C));
        $this->assertTrue($B->equals($D));
        $this->assertTrue($C->equals($A));
        $this->assertFalse($C->equals($B));
        $this->assertFalse($C->equals($D));
        $this->assertFalse($D->equals($A));
        $this->assertTrue($D->equals($B));
        $this->assertFalse($D->equals($C));
    }

    /**
     * @throws Exception
     * @throws TypeError
     */
    public function testRandomString()
    {
        $str = Base64UrlSafe::encode(random_bytes(32));

        $sets = [
            [true, true],
            [true, false],
            [false, true],
            [false, false]
        ];
        foreach ($sets as $set) {
            $hidden = new HiddenString($str, $set[0], $set[1]);

            ob_start();
            var_dump($hidden);
            $dump = ob_get_clean();
            $this->assertFalse(strpos($dump, $str));

            $print = \print_r($hidden, true);
            $this->assertFalse(strpos($print, $str));

            $cast = (string) $hidden;
            if ($set[0]) {
                $this->assertFalse(strpos($cast, $str));
            } else {
                $this->assertNotFalse(strpos($cast, $str));
            }

            $serial = serialize($hidden);
            if ($set[1]) {
                $this->assertFalse(strpos($serial, $str));
            } else {
                $this->assertNotFalse(strpos($serial, $str));
            }
        }
    }
}
