<?php
declare(strict_types=1);
namespace ParagonIE\Halite;

/**
 * Class HiddenString
 * @package ParagonIE\Halite
 */
final class HiddenString
{
    /**
     * @var string
     */
    protected $internalStringValue = '';

    /**
     * @var bool
     */
    protected $allowInline = false;

    /**
     * HiddenString constructor.
     * @param string $value
     * @param bool $allowInline
     */
    public function __construct(string $value, bool $allowInline = false)
    {
        $this->internalStringValue = Util::safeStrcpy($value);
        $this->allowInline = $allowInline;
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
        \Sodium\memzero($this->internalStringValue);
    }

    /**
     * Explicit invocation -- get the raw string value
     *
     * @return string
     */
    public function getString(): string
    {
        return Util::safeStrcpy($this->internalStringValue);
    }

    /**
     * Prevent accidental echoing of a hidden string
     *
     * @return string
     */
    public function __toString(): string
    {
        if ($this->allowInline) {
            return Util::safeStrcpy($this->internalStringValue);
        }
        return '';
    }
}
