<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use \ParagonIE\Halite\Util;
use \ParagonIE\Halite\Alerts\InvalidDigestLength;

/**
 * An implementation of a Merkle hash tree, built on the BLAKE2b hash function
 * (provided by libsodium)
 */
class MerkleTree
{
    const MERKLE_LEAF =   "\x01";
    const MERKLE_BRANCH = "\x00";

    private $rootCalculated = false;
    private $root = '';
    private $nodes = [];
    private $personalization = '';
    private $outputSize = \Sodium\CRYPTO_GENERICHASH_BYTES;
    
    /**
     * Instantiate a Merkle tree
     * 
     * @param Node[] $nodes
     */
    public function __construct(Node ...$nodes)
    {
        $this->nodes = $nodes;
    }
    
    /**
     * Get the root hash of this Merkle tree.
     *
     * @param bool $raw - Do we want a raw string instead of a hex string?
     * 
     * @return string
     */
    public function getRoot(bool $raw = false): string
    {
        if (!$this->rootCalculated) {
            $this->root = $this->calculateRoot();
        }
        return $raw
            ? $this->root
            : \Sodium\bin2hex($this->root);
    }
    
    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     * @param Node[] $nodes
     * @return MerkleTree
     */
    public function getExpandedTree(Node ...$nodes)
    {
        $thisTree = $this->nodes;
        foreach ($nodes as $node) {
            $thisTree []= $node;
        }
        return (new MerkleTree(...$thisTree))
            ->setHashSize($this->outputSize)
            ->setPersonalizationString($this->personalization);
    }

    /**
     * Set the hash output size.
     *
     * @param int $size
     * @return MerkleTree
     * @throws InvalidDigestLength
     */
    public function setHashSize(int $size): self
    {
        if ($size < \Sodium\CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new InvalidDigestLength(
                \sprintf(
                    'Merkle roots must be at least %d long.',
                    \Sodium\CRYPTO_GENERICHASH_BYTES_MIN
                )
            );
        }
        if ($size > \Sodium\CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new InvalidDigestLength(
                \sprintf(
                    'Merkle roots must be at most %d long.',
                    \Sodium\CRYPTO_GENERICHASH_BYTES_MAX
                )
            );
        }
        if ($this->outputSize !== $size) {
            $this->rootCalculated = false;
        }
        $this->outputSize = $size;
        return $this;
    }

    /**
     * Sets the personalization string for the Merkle root calculation
     *
     * @param string $str
     * @return MerkleTree
     */
    public function setPersonalizationString(string $str = ''): self
    {
        if ($this->personalization !== $str) {
            $this->rootCalculated = false;
        }
        $this->personalization = $str;
        return $this;
    }

    /**
     * Explicitly recalculate the Merkle root
     *
     * @return MerkleTree
     */
    public function triggerRootCalculation(): self
    {
        $this->root = $this->calculateRoot();
        return $this;
    }

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
        $order = self::getSizeRoundedUp($size);
        $hash = [];
        // Population (Use self::MERKLE_LEAF as a prefix)
        for ($i = 0; $i < $order; ++$i) {
            if ($i >= $size) {
                $hash[$i] = self::MERKLE_LEAF . $this->personalization . $this->nodes[$size - 1]->getHash(
                    true,
                    $this->outputSize,
                    $this->personalization
                );
            } else {
                $hash[$i] = self::MERKLE_LEAF . $this->personalization . $this->nodes[$i]->getHash(
                    true,
                    $this->outputSize,
                    $this->personalization
                );
            }
        }
        // Calculation (Use self::MERKLE_BRANCH as a prefix)
        do {
            $tmp = [];
            $j = 0;
            for ($i = 0; $i < $order; $i += 2) {
                if (empty($hash[$i + 1])) {
                    $tmp[$j] = Util::raw_hash(
                        self::MERKLE_BRANCH . $this->personalization . $hash[$i] . $hash[$i],
                        $this->outputSize
                    );
                } else {
                    $tmp[$j] = Util::raw_hash(
                        self::MERKLE_BRANCH . $this->personalization . $hash[$i] . $hash[$i + 1],
                        $this->outputSize
                    );
                }
                ++$j;
            }
            $hash = $tmp;
            $order >>= 1;
        } while ($order > 1);
        // We should only have one value left:t
        $this->rootCalculated = true;
        return \array_shift($hash);
    }

    /**
     * Let's go ahead and round up to the nearest mutliple of 2
     *
     * @param int $inputSize
     * @return int
     */
    public static function getSizeRoundedUp(int $inputSize): int
    {
        $order = 1;
        while($order < $inputSize) {
            $order <<= 1;
        }
        return $order;
    }
}
