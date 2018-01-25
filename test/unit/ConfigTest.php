<?php

use PHPUnit\Framework\TestCase;
use ParagonIE\Halite\Alerts\ConfigDirectiveNotFound;
use ParagonIE\Halite\Config;
use ParagonIE\Halite\Symmetric\Config as SymmetricConfig;

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

    public function testSymmetricConfig()
    {
        try {
            $config = SymmetricConfig::getConfig('');
            $this->fail('Invalid header allowed');
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame('Invalid version tag', $ex->getMessage());
        }
        try {
            $config = SymmetricConfig::getConfig('abcd');
            $this->fail('Invalid header allowed');
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame('Invalid version tag', $ex->getMessage());
        }
        try {
            $config = SymmetricConfig::getConfig("\x31\x42\x00\x00", 'seal');
            $this->fail('Invalid mode allowed');
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame('Invalid configuration mode: seal', $ex->getMessage());
        }
        try {
            $config = SymmetricConfig::getConfigEncrypt(1, 0);
            $this->fail('Unsupported mode allowed');
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame('Invalid version tag', $ex->getMessage());
        }
        try {
            $config = SymmetricConfig::getConfigAuth(1, 0);
            $this->fail('Unsupported mode allowed');
        } catch (\ParagonIE\Halite\Alerts\InvalidMessage $ex) {
            $this->assertSame('Invalid version tag', $ex->getMessage());
        }
    }
}
