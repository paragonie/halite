<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

class Node
{
    private $data;
    private $hash;
    
    public function __construct(string $data)
    {
        $this->data = $data;
        $this->hash = \Sodium\crypto_generichash($data);
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
     * @return string
     */
    public function getHash(bool $raw = false): string
    {
        if ($raw) {
            return $this->hash;
        }
        return \Sodium\bin2hex($this->hash);
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
