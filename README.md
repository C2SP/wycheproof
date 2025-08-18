# Project Wycheproof

Project Wycheproof is a [community managed](https://github.com/C2SP) repository
of test vectors that can be used by cryptography library developers to test 
against known attacks, specification inconsistencies, and other various 
implementation bugs.

Test vectors are maintained as JSON test vector data, with accompanying 
[JSON schema](https://json-schema.org/docs) files that document the structure 
of the test vector data.

## Getting started

1. Clone this repository. You may also want to integrate Wycheproof as a Git 
   submodule or otherwise set up automation to keep track of changes over time.
2. Write (_or generate from the JSON schema files_) code to load the vector data 
   as appropriate for your implementation language/project.
3. For each algorithm of interest, identify the inputs to your cryptography 
   APIs, and the produced outputs, mapping back to what the test vectors
   provide.
4. Iterate through applicable test vectors, ensuring that the results
   produced by your API when given the relevant input data matches the test 
   vector expected results.
5. For best results, integrate this process into your continuous integration 
   (CI) process so tests are run for all new contributions/changes.

You may find it helpful to examine how other projects like 
[pyca/cryptography](https://github.com/pyca/cryptography) have 
[integrated Wycheproof's test vectors](https://github.com/pyca/cryptography/tree/ec689a96c98037fc9929e830f551a85cac3973d3/tests/wycheproof).

## Coverage

Project Wycheproof has test vectors for the most popular crypto algorithms,
including

- AES-EAX
- AES-GCM
- ChaCha20-Poly1305
- [DH](doc/dh.md)
- DHIES
- [DSA](doc/dsa.md)
- [ECDH](doc/ecdh.md)
- ECDSA
- EdDSA
- ECIES
- HKDF
- HMAC
- [RSA](doc/rsa.md)
- X25519, X448
- ML-KEM (Kyber)
- ML-DSA (CRYSTALS-Dilithium)

The test vectors detect whether a library is vulnerable to many attacks,
including

*   Invalid curve attacks
*   Biased nonces in digital signature schemes
*   Of course, all Bleichenbacher’s attacks
*   And many more -- we have over 80 test cases

We welcome contribution of new test vector data, and algorithms.

## Contributing

If you want to contribute, please read [CONTRIBUTING](CONTRIBUTING.md) and send
us pull requests. You can also report bugs or request new tests as
[GitHub issues](https://github.com/C2SP/wycheproof/issues/new).

## Development Priorities

We're in the process of revitalizing development and maintenance of Project 
Wycheproof as a C2SP project with a renewed focus on the test vector data. 
Our immediate priorities are:

1. Consolidating `testvectors` and `testvectors_v1` into a single directory of
   test data.
2. Completing JSON schema descriptions of all test vectors.
3. Improving documentation and support for external contributors to provide
   new test data.
4. Developing a community of downstream consumers who can help sheppard 
   maintenance and review of new test vector data.
5. Adding additional algorithm and test case coverage to the test vector data.

## FAQ

### Why is the project called "Wycheproof"?

Project Wycheproof is named after 
[Mount Wycheproof](https://en.wikipedia.org/wiki/Mount_Wycheproof), the smallest
mountain in the world. The main motivation for the project at the time of its 
creation was to have a goal that is achievable. The smaller the mountain the 
more likely it is to be able to climb it.

### What downstream projects use Wycheproof testvectors?

Wycheproof test vectors are used in some form by a number of important
cryptography projects and libraries. In no particular order these include:

* [OpenSSL](https://openssl.org/)
* [BoringSSL](https://boringssl.googlesource.com/boringssl/)
* [aws-lc](https://github.com/aws/aws-lc)
* [LibreSSL](https://github.com/libressl/portable)
* [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html)
* [pyca/cryptography](https://cryptography.io/en/latest/)
* [Botan](https://botan.randombit.net/)
* [Go cryptography](https://golang.org)
* [swift-crypto](https://github.com/apple/swift-crypto)
* [RustCrypto](https://github.com/RustCrypto/)
* [Graviola](https://github.com/ctz/graviola)
* [Tink](https://developers.google.com/tink)
* [PyCryptdome](https://www.pycryptodome.org/)
* [OpenTitan](https://github.com/lowRISC/opentitan)
* [Zig](https://github.com/ziglang/zig)

If your project uses test vectors from Wycheproof, feel free to open a PR
to add it to the list above!

### Has Wycheproof testing found notable bugs?

See [doc/bugs.md](doc/bugs.md) for some notable historic bugs found using
Wycheproof's test harnesses, or test vector data.

### Should consuming projects use `testvectors` or `testvectors_v1`?

At the time of writing, projects should consider writing harness code to use
**both** vector data sources for maximum coverage. Some algorithms only have
coverage via `testvectors_v1` (e.g. ML-KEM, ML-DSA) while others are only
covered by `testvectors` data (e.g. `RsassaPkcs1Generate`).

We understand this situation is not ideal and are prioritizing an effort to
consolidate down to single source of test data. Stay tuned.

### Do all vectors have schemas?

At the time of writing, the following `testvectors_v1` files are missing schemas:

* `testvectors_v1/aes_ff1_base*_test.json`
* `testvectors_v1/aes_ff1_radix*_test.json`
* `testvectors_v1/ec_prime_order_curves_test.json`
* `testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json`
* `testvectors_v1/pbes2_hmacsha*_aes_*_test.json`
* `testvectors_v1/pbkdf2_hmacsha*_test.json`
* `testvectors_v1/rsa_pss_*_sha*_mgf*_params_test.json`
* `testvectors_v1/rsa_pss_misc_params_test.json`

Contribution of schemas for the above vectors would be most welcome.

### Is there additional documentation about test vectors?

Some legacy documentation for [files](doc/files.md), [formats](doc/formats.md) 
and [types](doc/types.md) are available, but not necessarily in-sync with the 
current test vector state. 

In general, prefer referencing the [schema files](schemas) since these are tested 
[in CI](https://github.com/cpu/wycheproof/actions/workflows/vectorlint.yml) to
ensure vector file contents match their advertised schema.

### Where is the test harness code?

Historically Wycheproof also included test harnesses (e.g. for Java and
Javascript cryptography implementations) that tested a variety of attacks
directly against implementations. Since transitioning to community support
these harnesses have [been removed][harness-rm] (but still exist in `git`
history for interested parties at [cd27d64]). Our current focus is on
implementation-agnostic test vectors.

Testing 3rd party cryptography libraries directly means flaws are only 
uncovered after they have been committed, and potentially released, by the
projects under test. Instead, we encourage downstream projects to regularly test
their code using Wycheproof test vectors as part of their development process.
This approach helps catch flaws _before_ they can become CVEs, means new 
features get tested immediately, and helps distribute the maintenance burden.
This allows the Wycheproof maintainers to focus on test vectors instead of 
tracking downstream development of many projects while simultaneously 
maintaining an ever-increasing number of language & project-specific test 
harnesses.

Parties interested in test harnesses may find continued work by 
Daniel Bleichenbacher in [Rooterberg](https://github.com/bleichenbacher-daniel/Rooterberg)
of interest.

[harness-rm]: https://github.com/C2SP/wycheproof/commit/d9b8297cc998fd1a11e64cdd585a671e8923f48b
[cd27d64]: https://github.com/C2SP/wycheproof/tree/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca

### Who created Wycheproof?

Project Wycheproof was originally created and maintained by:

*   Daniel Bleichenbacher
*   Thai Duong
*   Emilia Kasper
*   Quan Nguyen
*   Charles Lee
