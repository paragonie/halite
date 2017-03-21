<?php
declare(strict_types = 1);

use ParagonIE\Halite\Structure\{
    MerkleTree, Node
};

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class MerkleTreeTest extends \PHPUnit\Framework\TestCase
{
    public function testArithmetic()
    {
        $this->assertSame(1, MerkleTree::getSizeRoundedUp(1));
        $this->assertSame(2, MerkleTree::getSizeRoundedUp(2));
        $this->assertSame(4, MerkleTree::getSizeRoundedUp(3));
        $this->assertSame(4, MerkleTree::getSizeRoundedUp(4));
        $this->assertSame(8, MerkleTree::getSizeRoundedUp(5));
        $this->assertSame(8, MerkleTree::getSizeRoundedUp(6));
        $this->assertSame(8, MerkleTree::getSizeRoundedUp(7));
        $this->assertSame(8, MerkleTree::getSizeRoundedUp(8));
    }

    public function testExpectedBehavior()
    {
        $treeA = new MerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '6781891a87aa476454b74dc635c5cdebfc8f887438829ce2e81423f54906c058',
            $treeA->getRoot()
        );
        $treeB = new MerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e'),
            new Node('e'),
            new Node('e'),
            new Node('e')
        );
        $this->assertSame(
            $treeA->getRoot(),
            $treeB->getRoot()
        );

        $treeC = $treeA->getExpandedTree(
            new Node('e'),
            new Node('e'),
            new Node('e')
        );
        $this->assertSame(
            $treeA->getRoot(),
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

        $emptyTree = new MerkleTree();
        $this->assertSame(
            '',
            $emptyTree->getRoot()
        );
    }

    public function testDifferentHashSize()
    {
        $treeA = new MerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '6781891a87aa476454b74dc635c5cdebfc8f887438829ce2e81423f54906c058',
            $treeA->getRoot()
        );
        $treeA->setHashSize(\Sodium\CRYPTO_GENERICHASH_BYTES_MAX);
        $this->assertSame(
            '0e97a7c708bc8350809ecbeb941d9338af894c37d5fbfb6c3aa2f7ee0bc798f07d7505f33c5b6a6200c191efc51d9c4c0fd2d1397fe7291628aee424ff9093c3',
            $treeA->getRoot()
        );
    }

    public function testPersonalizedHash()
    {
        $treeA = new MerkleTree(
            new Node('a'),
            new Node('b'),
            new Node('c'),
            new Node('d'),
            new Node('e')
        );
        $this->assertSame(
            '6781891a87aa476454b74dc635c5cdebfc8f887438829ce2e81423f54906c058',
            $treeA->getRoot()
        );
        $treeA->setPersonalizationString('Halite unit test framework');
        $this->assertSame(
            'e912ee25c680b0e3ee30b52eec0f0d79b502e15c9091c19cec7afc3115260b78',
            $treeA->getRoot()
        );
    }
}
