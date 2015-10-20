<?php
namespace ParagonIE\Halite;

/**
 * This is just an abstract class that hosts some constants
 */
abstract class Halite
{
    const VERSION             = '0.6.0';
    const HALITE_VERSION      = "\x31\x42\x00\x06";
    // \x31\x42 => 3.142 (approx. pi)
    // Because pi is the symbol we use for Paragon Initiative Enterprises
    // \x00\x01 => version 0.01
    const HALITE_VERSION_FILE = "\x31\x41\x00\x06";
    // This must never change:
    const VERSION_TAG_LEN = 4;
}
