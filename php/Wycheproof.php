<?php
declare(strict_types=1);
namespace C2sp\Wycheproof;

class Wycheproof
{
    const DEFAULT_TEST_VECTOR_DIR_NAME = 'testvectors_v1';

    private string $testVectorRoot;

    public function __construct(?string $testVectorRoot = null)
    {
        if (is_null($testVectorRoot)) {
            // Default to where ever the test vectors are installed locally
            $testVectorRoot = dirname(__DIR__) .
                DIRECTORY_SEPARATOR .
                self::DEFAULT_TEST_VECTOR_DIR_NAME;
        }
        $testVectorRoot = realpath($testVectorRoot);
        if (!is_dir($testVectorRoot)) {
            throw new WycheproofException('Cannot read directory');
        }
        $this->testVectorRoot = $testVectorRoot;
    }

    /**
     * Returns a list of file paths that can be used with fopen() or
     * file_get_contents()
     *
     * @return array<string, string>
     */
    public function listTestVectorFiles(): array
    {
        $files = [];
        foreach (glob($this->testVectorRoot . DIRECTORY_SEPARATOR . '*.json') as $file) {
            $realpath = realpath($file);
            if (!is_string($realpath)) {
                continue;
            }
            if (!str_starts_with($realpath, $this->testVectorRoot)) {
                continue;
            }
            $test_name = preg_replace('#/(.+?)\.json$#', '$1', $file);
            $files[$test_name] = $file;
        }
        return $files;
    }
}
