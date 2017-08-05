<?php
declare(strict_types=1);

use ParagonIE\Halite\HiddenString;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @covers HiddenString
 */
class HiddenStringTest extends TestCase
{
    public function testRandomString()
    {
        $str = Base64UrlSafe::encode(\random_bytes(32));

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
            $this->assertFalse(\strpos($dump, $str));

            $print = \print_r($hidden, true);
            $this->assertFalse(\strpos($print, $str));

            $cast = (string) $hidden;
            if ($set[0]) {
                $this->assertFalse(\strpos($cast, $str));
            } else {
                $this->assertNotFalse(\strpos($cast, $str));
            }

            $serial = \serialize($hidden);
            if ($set[1]) {
                $this->assertFalse(\strpos($serial, $str));
            } else {
                $this->assertNotFalse(\strpos($serial, $str));
            }
        }
    }
}
