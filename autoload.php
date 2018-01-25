<?php
if (file_exists(__DIR__.'/vendor/autoload.php')) {
    require __DIR__.'/vendor/autoload.php';
} else {
    /**
     * You aren't using Composer, so, here's an autoloader instead.
     */
    spl_autoload_register(function ($class) {
        $prefix = 'ParagonIE\\Halite\\';
        $base_dir = __DIR__.'/src/';

        // Does the class use the namespace prefix?
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            // no, move to the next registered autoloader
            return;
        }

        // Get the relative class name
        $relative_class = substr($class, $len);

        // Replace the namespace prefix with the base directory, replace namespace
        // separators with directory separators in the relative class name, append
        // with .php
        $file = $base_dir.
            str_replace(
                ['\\', '_'],
                '/',
                $relative_class
            ).'.php';

        // If the file exists, require it
        if (file_exists($file) && strpos(realpath($file), $base_dir) === 0) {
            require $file;
        }
    });
}
