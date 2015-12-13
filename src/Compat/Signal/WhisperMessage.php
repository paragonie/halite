<?php
namespace ParagonIE\Halite\Compat\Signal;

/**
 * This is what's stored in memory.
 */
class WhisperMessage
{
    protected $ephemeralKey;
    protected $counter;
    protected $previousCounter;
    protected $ciphertext;
}
