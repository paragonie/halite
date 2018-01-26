<?php
declare(strict_types=1);

use ParagonIE\Halite\Structure\Node;
use PHPUnit\Framework\TestCase;

final class NodeTest extends TestCase
{
    /**
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     */
    public function testHash()
    {
        $stringData = random_bytes(32);
        $hash = sodium_crypto_generichash($stringData);
        $node = new Node($stringData);

        $this->assertSame($stringData, $node->getData());
        $this->assertSame(bin2hex($hash), $node->getHash());
        $this->assertSame($hash, $node->getHash(true));

        $extra = random_bytes(32);
        $hash = sodium_crypto_generichash($stringData . $extra);

        $this->assertSame(bin2hex($hash), $node->getExpandedNode($extra)->getHash());
        $this->assertSame($hash, $node->getExpandedNode($extra)->getHash(true));
    }
}
