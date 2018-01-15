<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

/**
 * Class HiddenString
 *
 * The purpose of this class is to encapsulate strings and hide their contents
 * from stack traces should an unhandled exception occur in a program that uses
 * Halite.
 *
 * The only things that should be protected:
 * - Passwords
 * - Plaintext (before encryption)
 * - Plaintext (after decryption)
 *
 * This library makes heavy use of return-type declarations,
 * which are a PHP 7 only feature. Read more about them here:
 *
 * @ref http://php.net/manual/en/functions.returning-values.php#functions.returning-values.type-declaration
 *
 * @package ParagonIE\Halite
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
final class HiddenString
{
    /**
     * @var string
     */
    protected $internalStringValue = '';

    /**
     * Disallow the contents from being accessed via __toString()?
     *
     * @var bool
     */
    protected $disallowInline = false;

    /**
     * Disallow the contents from being accessed via __sleep()?
     *
     * @var bool
     */
    protected $disallowSerialization = false;

    /**
     * HiddenString constructor.
     * @param string $value
     * @param bool $disallowInline
     * @param bool $disallowSerialization
     *
     * @throws \TypeError
     */
    public function __construct(
        string $value,
        bool $disallowInline = false,
        bool $disallowSerialization = false
    ) {
        $this->internalStringValue = Util::safeStrcpy($value);
        $this->disallowInline = $disallowInline;
        $this->disallowSerialization = $disallowSerialization;
    }

    /**
     * @param HiddenString $other
     * @return bool
     * @throws \TypeError
     */
    public function equals(HiddenString $other)
    {
        return \hash_equals(
            $this->getString(),
            $other->getString()
        );
    }

    /**
     * Hide its internal state from var_dump()
     *
     * @return array
     */
    public function __debugInfo()
    {
        return [
            'internalStringValue' =>
                '*',
            'attention' =>
                'If you need the value of a HiddenString, ' .
                'invoke getString() instead of dumping it.'
        ];
    }

    /**
     * Wipe it from memory after it's been used.
     */
    public function __destruct()
    {
        \sodium_memzero($this->internalStringValue);
    }

    /**
     * Explicit invocation -- get the raw string value
     *
     * @return string
     * @throws \TypeError
     */
    public function getString(): string
    {
        return Util::safeStrcpy($this->internalStringValue);
    }

    /**
     * Returns a copy of the string's internal value, which should be zeroed.
     * Optionally, it can return an empty string.
     *
     * @return string
     * @throws \TypeError
     */
    public function __toString(): string
    {
        if (!$this->disallowInline) {
            return Util::safeStrcpy($this->internalStringValue);
        }
        return '';
    }

    /**
     * @return array
     */
    public function __sleep(): array
    {
        if (!$this->disallowSerialization) {
            return [
                'internalStringValue',
                'disallowInline',
                'disallowSerialization'
            ];
        }
        return [];
    }
}
