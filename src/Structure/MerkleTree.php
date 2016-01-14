<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

/**
 * An implementation of a Merkle hash tree, built on the BLAKE2b hash function
 * (provided by libsodium)
 */
class MerkleTree
{
    const MERKLE_LEAF =   "\x01";
    const MERKLE_BRANCH = "\x00";
    
    private $root = '';
    private $needs_recalc = true;
    private $nodes = [];
    
    /**
     * Instantiate a Merkle tree
     * 
     * @param array $nodes
     */
    private function __construct(Node ...$nodes)
    {
        
    }
    
    /**
     * 
     * @param bool $raw - Do we want a raw string instead of a hex string?
     * 
     * @return string
     */
    public function getRoot($raw = false)
    {
        
    }
    
    /**
     * Add a node to this Merkle Tree
     * 
     * 
     */
    public function addNode(Node $node)
    {
        $this->nodes []= $node;
        $this->needs_recalc = true;
    }
    
    /**
     * Idiomatic helper method for adding multiple nodes at once:
     */
    public function addNodes(Node ...$nodes)
    {
        foreach ($nodes as $node) {
            $this->addNode($node);
        }
        return !empty($nodes);
    }
}
