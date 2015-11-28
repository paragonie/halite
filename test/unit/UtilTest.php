<?php
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Util;

/**
 * Halite Util test case
 *
 * @category   HaliteTest
 * @package    Halite
 * @author     Stefanie Schmidt <stefanie@reneschmidt.de>
 * @license    http://opensource.org/licenses/GPL-3.0 GPL 3
 * @link       https://paragonie.com/project/halite
 */
class UtilTest extends PHPUnit_Framework_TestCase
{
    /**
     * test safeStrLen() with illegal parameter. We expect to see an exception
     * @return void
     * @throws CannotPerformOperation
     */
    public function testSafeStrlen()
    {
        $this->setExpectedException('\ParagonIE\Halite\Alerts\HaliteAlert');

        $teststring = []; // is not a string, will provoke a warning

        //suppress php warning
        Util::safeStrlen($teststring);
    }
}
