<?php

use \ParagonIE\Halite\Structure\{
    MerkleTree,
    Node
};

/**
 * @backupGlobals disabled
 * @backupStaticAttributes disabled
 */
class MerkleTreeTest extends PHPUnit_Framework_TestCase
{
    public function testArithmetic()
    {
        $this->assertEquals(1, MerkleTree::getSizeRoundedUp(1));
        $this->assertEquals(2, MerkleTree::getSizeRoundedUp(2));
        $this->assertEquals(4, MerkleTree::getSizeRoundedUp(3));
        $this->assertEquals(4, MerkleTree::getSizeRoundedUp(4));
        $this->assertEquals(8, MerkleTree::getSizeRoundedUp(5));
        $this->assertEquals(8, MerkleTree::getSizeRoundedUp(6));
        $this->assertEquals(8, MerkleTree::getSizeRoundedUp(7));
        $this->assertEquals(8, MerkleTree::getSizeRoundedUp(8));
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
        $this->assertEquals(
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
        $this->assertEquals(
            $treeA->getRoot(),
            $treeB->getRoot()
        );
        
        $treeC = $treeA->getExpandedTree(
            new Node('e'),
            new Node('e'),
            new Node('e')
        );
        $this->assertEquals(
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
    }
}