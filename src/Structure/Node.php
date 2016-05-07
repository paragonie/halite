<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use \ParagonIE\Halite\Util;

class Node
{
    private $data;
    
    public function __construct(string $data)
    {
        $this->data = $data;
    }

    /**
     * Get the data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Get a hash of the data (defaults to hex encoded)
     *
     * @param bool $raw
     *
     * These two aren't really meant to be used externally:
     * @param int $outputSize
     * @param string $personalization
     *
     * @return string
     */
    public function getHash(
        bool $raw = false,
        int $outputSize = \Sodium\CRYPTO_GENERICHASH_BYTES,
        string $personalization = ''
    ): string {
        if ($raw) {
            return Util::raw_hash(
                $personalization . $this->data,
                $outputSize
            );
        }
        return Util::hash(
            $personalization . $this->data,
            $outputSize
        );
    }

    /**
     * Nodes are immutable, but you can create one with extra data.
     *
     * @param string $concat
     * @return Node
     */
    public function getExpandedNode(string $concat): Node
    {
        return new Node($this->data . $concat);
    }
}
