<?php
declare(strict_types=1);
namespace ParagonIE\Halite\Structure;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Util;

/**
 * Class Node
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
class Node
{
    /**
     * @var string
     */
    private $data;

    /**
     * Node constructor.
     * @param string $data
     */
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
     * @throws CannotPerformOperation
     * @throws \TypeError
     */
    public function getHash(
        bool $raw = false,
        int $outputSize = \SODIUM_CRYPTO_GENERICHASH_BYTES,
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
