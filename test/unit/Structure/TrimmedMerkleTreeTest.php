<?php
declare(strict_types=1);

use ParagonIE\Halite\Structure\{
    MerkleTree,
    Node,
    TrimmedMerkleTree
};
use PHPUnit\Framework\TestCase;

final class TrimmedMerkleTreeTest extends TestCase
{

    public function testExpectedBehavior()
    {
        $treeA = new TrimmedMerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '8dc7ee23d6b29df641ac78a8c56bb2e0379015eeb06e1a01feb8bb617d6272f6',
            $treeA->getRoot()
        );
        $treeB = new TrimmedMerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e'),
            new Node('e'),
            new Node('e'),
            new Node('e')
        );
        $this->assertNotSame(
            $treeA->getRoot(),
            $treeB->getRoot()
        );

        $treeC = $treeA->getExpandedTree(
            new Node('e'),
            new Node('e'),
            new Node('e')
        );
        $this->assertSame(
            get_class($treeB),
            get_class($treeC)
        );
        $this->assertSame(
            $treeB->getRoot(),
            $treeC->getRoot()
        );
        $treeD = $treeA->getExpandedTree(
            new Node('f'),
            new Node('e'),
            new Node('e')
        );
        $this->assertNotEquals(
            $treeA->getRoot(),
            $treeD->getRoot()
        );

        $emptyTree = new TrimmedMerkleTree();
        $this->assertSame(
            '',
            $emptyTree->getRoot()
        );
    }

    public function testDifferentHashSize()
    {
        $treeA = new TrimmedMerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '8dc7ee23d6b29df641ac78a8c56bb2e0379015eeb06e1a01feb8bb617d6272f6',
            $treeA->getRoot()
        );
        $treeA->setHashSize(SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $this->assertSame(
            'd25cb4ca1eb8bbf882376a3d66a33c91c7005386b8312979a003110323495e9c6e91701837d59dc798b84eed8cfa59a4763b61c54bbe2c502b9386da88c938e1',
            $treeA->getRoot()
        );
    }

    public function testPersonalizedHash()
    {
        $treeA = new TrimmedMerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '8dc7ee23d6b29df641ac78a8c56bb2e0379015eeb06e1a01feb8bb617d6272f6',
            $treeA->getRoot()
        );
        $treeA->setPersonalizationString('Halite unit test framework');
        $this->assertSame(
            'ae2e4caf8f7da8ed84fb22157870e31fee0646f4757dcf1c01367817500a205d',
            $treeA->getRoot()
        );
    }

    public function testCompat()
    {
        $treeA = new MerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d')
        );
        $treeB = new TrimmedMerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d')
        );
        $this->assertSame(
            $treeA->getRoot(),
            $treeB->getRoot()
        );

        $personal = random_bytes(32);
        $treeA->setPersonalizationString($personal);
        $treeB->setPersonalizationString($personal);
        $this->assertSame(
            $treeA->getRoot(),
            $treeB->getRoot()
        );
    }
}
