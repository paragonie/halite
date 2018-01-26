<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use ParagonIE\Halite\Alerts\{
    CannotPerformOperation,
    InvalidDigestLength
};
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
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Structure
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
class TrimmedMerkleTree extends MerkleTree
{
    /**
     * Calculate the Merkle root, taking care to distinguish between
     * leaves and branches (0x01 for the nodes, 0x00 for the branches)
     * to protect against second-preimage attacks
     *
     * @return string
     * @throws CannotPerformOperation
     * @throws \TypeError
     * @psalm-suppress EmptyArrayAccess Psalm is misreading array elements
     */
    protected function calculateRoot(): string
    {
        $size = \count($this->nodes);
        if ($size < 1) {
            return '';
        }
        /** @var array<int, string> $hash */
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
            /** @var array<int, string> $tmp */
            $tmp = [];
            $j = 0;
            for ($i = 0; $i < $size; $i += 2) {
                if (empty($hash[$i + 1])) {
                    $tmp[$j] = $hash[$i];
                } elseif(!empty($hash[$i])) {
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
            /** @var array<int, string> $hash */
            $hash = $tmp;
            $size >>= 1;
        } while ($size > 1);

        // We should only have one value left:
        $this->rootCalculated = true;
        /** @var string $first */
        $first = \array_shift($hash);
        return $first;
    }

    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     * @param array<int, Node> $nodes
     * @return TrimmedMerkleTree
     * @throws InvalidDigestLength
     */
    public function getExpandedTree(Node ...$nodes): MerkleTree
    {
        $thisTree = $this->nodes;
        foreach ($nodes as $node) {
            $thisTree []= $node;
        }
        $new = new TrimmedMerkleTree(...$thisTree);
        $new->setHashSize($this->outputSize);
        $new->setPersonalizationString($this->personalization);
        return $new;
    }
}
