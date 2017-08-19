<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Halite\Util;
use ParagonIE\Halite\Alerts\InvalidDigestLength;

/**
 * Class MerkleTree
 *
 * An implementation of a Merkle hash tree, built on the BLAKE2b hash function
 * (provided by libsodium)
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite\Structure
 */
class MerkleTree
{
    const MERKLE_LEAF =   "\x01";
    const MERKLE_BRANCH = "\x00";

    /**
     * @var bool
     */
    protected $rootCalculated = false;

    /**
     * @var string
     */
    protected $root = '';

    /**
     * @var Node[]
     */
    protected $nodes = [];

    /**
     * @var string
     */
    protected $personalization = '';
    
    /**
     * @var int
     */
    protected $outputSize = \SODIUM_CRYPTO_GENERICHASH_BYTES;
    
    /**
     * Instantiate a Merkle tree
     * 
     * @param array<int, Node> $nodes
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
            : Hex::encode($this->root);
    }
    
    /**
     * Merkle Trees are immutable. Return a replacement with extra nodes.
     *
     * @param array<int, Node> $nodes
     * @return MerkleTree
     */
    public function getExpandedTree(Node ...$nodes): MerkleTree
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
     * @return self
     * @throws InvalidDigestLength
     */
    public function setHashSize(int $size): self
    {
        if ($size < \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN) {
            throw new InvalidDigestLength(
                \sprintf(
                    'Merkle roots must be at least %d long.',
                    \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN
                )
            );
        }
        if ($size > \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX) {
            throw new InvalidDigestLength(
                \sprintf(
                    'Merkle roots must be at most %d long.',
                    \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX
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
     * @return self
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
     * @return self
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
                $hash[$i] = self::MERKLE_LEAF .
                    $this->personalization .
                    $this->nodes[$size - 1]->getHash(
                        true,
                        $this->outputSize,
                        $this->personalization
                    );
            } else {
                $hash[$i] = self::MERKLE_LEAF .
                    $this->personalization .
                    $this->nodes[$i]->getHash(
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
                        self::MERKLE_BRANCH .
                            $this->personalization .
                            $hash[$i] .
                            $hash[$i],
                        $this->outputSize
                    );
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
            $order >>= 1;
        } while ($order > 1);
        // We should only have one value left:t
        $this->rootCalculated = true;
        /** @var string $first */
        $first = \array_shift($hash);
        return $first;
    }

    /**
     * Let's go ahead and round up to the nearest multiple of 2
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
