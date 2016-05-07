<?php
declare(strict_types=1);

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