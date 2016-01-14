<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

class BlockChain
{
    private $trees;
    private $lastHash;
    
    /**
     * A block chain data structure
     * 
     * @param string $startHash The hash from which we begin loading trees
     * @param MerkleTree $trees
     */
    public function __construct(string $startHash = null, MerkleTree ...$trees)
    {
        
    }
}