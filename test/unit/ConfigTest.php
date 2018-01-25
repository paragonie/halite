<?php

use PHPUnit\Framework\TestCase;
use ParagonIE\Halite\Alerts\ConfigDirectiveNotFound;
use ParagonIE\Halite\Config;

class ConfigTest extends TestCase
{
    public function testConfig()
    {
        $config = new Config([
            'abc' => 12345
        ]);

        $this->assertSame(12345, $config->abc);
        try {
            $x = $config->missing;
            $this->fail('Missing configuration allowed');
        } catch (ConfigDirectiveNotFound $ex) {
            $this->assertSame('missing', $ex->getMessage());
        }
    }
}
