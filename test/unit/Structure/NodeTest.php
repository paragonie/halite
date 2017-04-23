<?php
declare(strict_types = 1);

use ParagonIE\Halite\Structure\Node;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class NodeTest extends PHPUnit_Framework_TestCase
{
    public function testHash()
    {
        $stringData = \random_bytes(32);
        $hash       = \Sodium\crypto_generichash($stringData);
        $node       = new Node($stringData);

        $this->assertSame($stringData, $node->getData());
        $this->assertSame($hash, $node->getHash(true));
    }
}