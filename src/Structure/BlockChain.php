<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

class BlockChain
{
    private $startHash;
    private $trees;
    private $lastHash;
    
    /**
     * A block chain data structure
     * 
     * @param string $startHash The hash from which we begin loading trees
     * @param MerkleTree[] $trees
     */
    public function __construct(string $startHash = '', MerkleTree ...$trees)
    {
        $this->startHash = $startHash;
        $this->trees = $trees;
        $this->lastHash = $this->calculateHash();
    }

    public function getHash(bool $raw = false): string
    {
        if ($raw) {
            return $this->lastHash;
        }
        return \Sodium\bin2hex($this->lastHash);
    }

    /**
     *
     * @return string
     */
    protected function calculateHash(): string
    {
        $numTrees = \count($this->trees);
        $hash = $this->startHash;
        for ($i = 0; $i < $numTrees; ++$i) {
            $hash = \Sodium\crypto_generichash(
                $this->trees[$i]->getRoot(true),
                $hash
            );
        }
        return $hash;
    }
}
