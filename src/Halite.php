<?php
namespace ParagonIE\Halite;

/**
 * This is just an abstract class that hosts some constants
 * 
 * Version Tag Info:
 * 
 *  \x31\x41 => 3.141 (approx. pi)
 *  \x31\x42 => 3.142 (approx. pi)
 *  Because pi is the symbol we use for Paragon Initiative Enterprises
 *  \x00\x07 => version 0.07
 */
abstract class Halite
{
    const VERSION             = '1.0.0';

    const HALITE_VERSION_KEYS = "\x31\x40\x01\x00";
    const HALITE_VERSION_FILE = "\x31\x41\x01\x00";
    const HALITE_VERSION      = "\x31\x42\x01\x00";
    
    const VERSION_TAG_LEN = 4;
}
