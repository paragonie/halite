<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use ParagonIE\Halite\Util;

/**
 * Class TrimmedMerkleTree
 *
 * A variant of a Merkle tree that silently passes the dangling nodes up
 * instead of duplicating and then hashing.
 *
 * If you're planning to implement this into some sort of crypto-currency,
 * you'll almost certainly want to use the Trimmed variant.
 *
 * @package ParagonIE\Halite\Structure
 */
class TrimmedMerkleTree extends MerkleTree
{
    /**
     * Calculate the Merkle root, taking care to distinguish between
     * leaves and branches (0x01 for the nodes, 0x00 for the branches)
     * to protect against second-preimage attacks
     *
     * @return string
     */
    protected function calculateRoot(): string
    {
        $size = \count($this->nodes);
        if ($size < 1) {
            return '';
        }
        $hash = [];
        // Population (Use self::MERKLE_LEAF as a prefix)
        for ($i = 0; $i < $size; ++$i) {
            $hash[$i] = self::MERKLE_LEAF .
                $this->personalization .
                $this->nodes[$i]->getHash(
                    true,
                    $this->outputSize,
                    $this->personalization
                );
        }

        // Calculation (Use self::MERKLE_BRANCH as a prefix)
        do {
            $tmp = [];
            $j = 0;
            for ($i = 0; $i < $size; $i += 2) {
                if (empty($hash[$i + 1])) {
                    $tmp[$j] = $hash[$i];
                } else {
                    $tmp[$j] = Util::raw_hash(
                        self::MERKLE_BRANCH .
                            $this->personalization .
                            $hash[$i] .
                            $hash[$i + 1],
                        $this->outputSize
                    );
                }
                ++$j;
            }
            $hash = $tmp;
            $size >>= 1;
        } while ($size > 1);
        // We should only have one value left:t
        $this->rootCalculated = true;
        return \array_shift($hash);
    }

    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     * @param Node[] $nodes
     * @return MerkleTree
     */
    public function getExpandedTree(Node ...$nodes): MerkleTree
    {
        $thisTree = $this->nodes;
        foreach ($nodes as $node) {
            $thisTree []= $node;
        }
        return (new TrimmedMerkleTree(...$thisTree))
            ->setHashSize($this->outputSize)
            ->setPersonalizationString($this->personalization);
    }
}