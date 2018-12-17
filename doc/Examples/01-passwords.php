<?php
declare(strict_types=1);
use ParagonIE\Halite\Password;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\HiddenString\HiddenString;

try {
    // First, manage the keys
    if (!file_exists('01-secret-key.txt')) {
        $secretKey = KeyFactory::generateEncryptionKey();
        KeyFactory::save($secretKey, '01-secret-key.txt');
    } else {
        $secretKey = KeyFactory::loadEncryptionKey('01-secret-key.txt');
    }

    $password = new HiddenString('correct horse battery staple');
    $hash = Password::hash($password, $secretKey);

    if (Password::verify($password, $hash, $secretKey)) {
        echo 'Access granted', "\n";
    } else {
        echo 'Access DENIED!', "\n";
        exit(255);
    }
} catch (Throwable $ex) {
    echo $ex->getMessage(), PHP_EOL;
    echo $ex->getTraceAsString(), PHP_EOL;
    exit(127);
}
