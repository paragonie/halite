<?php
/**
 * Grabs a random file and tells you to audit it.
 */
require_once dirname(__DIR__).'/vendor/autoload.php';

/**
 * List all the files in a directory (and subdirectories)
 *
 * @param string $folder - start searching here
 * @param string $extension - extensions to match
 *
 * @return array
 */
function list_all_files(string $folder, string $extension = '*'): array
{
    $dir = new RecursiveDirectoryIterator($folder);
    $ite = new RecursiveIteratorIterator($dir);
    if ($extension === '*') {
        $pattern = '/.*/';
    } else {
        $pattern = '/.*\.' . preg_quote($extension, '/') . '$/';
    }
    $files = new RegexIterator($ite, $pattern, RegexIterator::GET_MATCH);
    $fileList = [];
    foreach($files as $file) {
        if (is_array($file)) {
            foreach ($file as $i => $f) {
                // Prevent . and .. from being treated as valid files:
                $check = preg_replace('#^(.+?)/([^/]+)$#', '$2', $f);
                if ($check === '.' || $check === '..') {
                    unset($file[$i]);
                }
            }
        }
        $fileList = array_merge($fileList, $file);
    }
    return $fileList;
}

if ($argc > 1) {
    $extensions = array_slice($argv, 1);
} else {
    $extensions = ['php', 'twig'];
}
$fileList = [];
foreach ($extensions as $ex) {
    foreach (list_all_files(dirname(__DIR__) . '/src/', $ex) as $file) {
        $fileList []= $file;
    }
}

$choice = random_int(0, count($fileList) - 1);

echo "Audit this file:\n\t";

$l = strlen(dirname(__DIR__));

echo substr($fileList[$choice], $l), "\n";
