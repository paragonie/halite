<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Base64UrlSafe
use ParagonIE\Halite\{
    Symmetric\EncryptionKey;
    HiddenString;
    Cookie;
};
use PHPUnit\Framework\TestCase;

final class CookieTest extends TestCase
{
    public function test__debugInfo()
    {
        $str = Base64UrlSafe::encode(random_bytes(32));
        $cookie = new Cookie(new EncryptionKey(new HiddenString()));
        $this->assertEquals([ 'key' => 'private' ], $cookie->__debugInfo());
        $this->assertTrue([ 'key' => $str ] !== $cookie->__debugInfo());
    }

}
