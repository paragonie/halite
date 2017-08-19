<?php
declare(strict_types=1);

use ParagonIE\Halite\Structure\Node;
use PHPUnit\Framework\TestCase;

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class NodeTest extends TestCase
{
    public function testHash()
    {
        $stringData = \random_bytes(32);
        $hash = sodium_crypto_generichash($stringData);
        $node = new Node($stringData);

        $this->assertSame($stringData, $node->getData());
        $this->assertSame($hash, $node->getHash(true));
    }
}