# Wycheproof for PHP

This does not implement a complete testing harness for PHP software.
This code exists to expose Wycheproof test vectors to the PHP ecosystem and 
provide a simple way to get the file paths for all test vectors.

Users are responsible for selecting the test vector file they are interested in,
decoding the JSON file, iterating over the objects, and interacting with their
chosen cryptography implementation.
