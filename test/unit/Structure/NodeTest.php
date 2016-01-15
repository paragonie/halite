<?php

use \ParagonIE\Halite\Structure\Node;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class NodeTest extends PHPUnit_Framework_TestCase
{
    public function testHash()
    {
        $stringData = \random_bytes(32);
        $hash = \Sodium\crypto_generichash($stringData);
        $node = new Node($stringData);

        $this->assertEquals($stringData, $node->getData());
        $this->assertEquals($hash, $node->getHash(true));
    }
}