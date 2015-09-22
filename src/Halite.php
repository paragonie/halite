<?php
namespace ParagonIE\Halite;

/**
 * This is just an abstract class that hosts some constants
 */
abstract class Halite
{
    const VERSION = '0.1.0';
    const HALITE_VERSION = "\x31\x42\x00\x01";
    // \x31\x42 => 3.142 (approx. pi)
    // Because pi is the symbol we use for Paragon Initiative Enterprises
    // \x00\x01 => version 0.01
    
    const HKDF_SBOX = 'Halite|EncryptionKey';
    const HKDF_AUTH = 'AuthenticationKeyFor_|Halite';
    const VERSION_TAG_LEN = 4;
    const HKDF_SALT_LEN = 32;
}
