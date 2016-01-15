<?php
use \ParagonIE\Halite\Halite;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class HaliteTest extends PHPUnit_Framework_TestCase
{
    public function testLibsodiumDetection()
    {
        $this->assertTrue(
            Halite::isLibsodiumSetupCorrectly()
        );
    }
}