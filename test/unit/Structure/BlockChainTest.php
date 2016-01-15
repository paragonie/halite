<?php
declare(strict_types=1);

use \ParagonIE\Halite\Structure\{
    BlockChain,
    MerkleTree,
    Node
};

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class BlockChainTest extends PHPUnit_Framework_TestCase
{
    public function testChain()
    {
        $trees = [
            new MerkleTree(
                new Node('418 i am a little teapot'),
                new Node('yellow submarine'),
                new Node('paragon initiative enterprises'),
                new Node('application security')
            ),
            new MerkleTree(
                new Node('cryptography'),
                new Node('engineering'),
                new Node('for complete noobcakes')
            ),
            new MerkleTree(
                new Node('418 i am a little teapot'),
                new Node('yellow submarine'),
                new Node('paragon initiative enterprises'),
                new Node('application security'),
                new Node('cryptography'),
                new Node('engineering'),
                new Node('for complete noobcakes')
            )
        ];
        $begin = \Sodium\crypto_generichash('GENESIS BLOCK');
        $bc1 = new BlockChain($begin, $trees[0]);
        $bc2 = new BlockChain($bc1->getHash(true), $trees[1]);
        $bc3 = new BlockChain($begin, $trees[0], $trees[1]);
        $bc4 = new BlockChain($begin, $trees[2]);

        $treeTest = $trees[0]->getExpandedTree(
            new Node('cryptography'),
            new Node('engineering'),
            new Node('for complete noobcakes')
        );
        $bc5 = new BlockChain($begin, $treeTest);

        // The output of one block feeding into the next should match:
        $this->assertEquals($bc2->getHash(), $bc3->getHash());

        // We shouldn't allow blocks to be appeneded:
        $this->assertNotEquals($bc3->getHash(), $bc4->getHash());

        // However, if we create a new block, it should be OK:
        $this->assertEquals($bc4->getHash(), $bc5->getHash());
    }
}
