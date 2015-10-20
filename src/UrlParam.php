<?php

namespace ParagonIE\Halite;

abstract class UrlParam
{
    public static function encrypt($string, Key $key)
    {
        throw new \Exception("Encryption is not the right tool for this job. https://paragonie.com/b/oMFJhGJ0aSgCaZq0");
    }
    public static function decrypt($string, Key $key)
    {
        return self::encrypt($string, $key);
    }
}