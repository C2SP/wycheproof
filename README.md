# Project Wycheproof

Project Wycheproof is a [community managed](https://github.com/C2SP) repository
of test vectors that can be used by cryptography library developers to test 
against known attacks, specification inconsistencies, and other various 
implementation bugs.

Test vectors are maintained as JSON test vector data, with accompanying 
[JSON schema](https://json-schema.org/docs) files that document the structure 
of the test vector data.

> [!NOTE]
> Hello RWC 2024 attendees and others! Wycheproof recently moved to community
> maintenance thanks to the shared efforts of Google and C2SP.
> We are still working to update the README and documentation,
> but we welcome your feedback and look forward to your contributions!

### Contributing

If you want to contribute, please read [CONTRIBUTING](CONTRIBUTING.md) and send
us pull requests. You can also report bugs or request new tests as 
[GitHub issues](https://github.com/C2SP/wycheproof/issues/new).

## Introduction

Project Wycheproof contains test vectors that can be used to test crypto
libraries against known attacks.

Unfortunately, in cryptography, subtle mistakes can have catastrophic
consequences, and we found that libraries fall into such implementation
pitfalls much too often and for much too long. Good implementation guidelines,
however, are hard to come by: understanding how to implement cryptography
securely requires digesting decades' worth of academic literature. We recognize
that software engineers fix and prevent bugs with unit testing, and we found
that cryptographic loopholes can be resolved by the same means.

These observations have prompted us to develop Project Wycheproof, a collection
of test vectors that detect known weaknesses or check for expected behaviors of
some cryptographic algorithm. Project Wycheproof provides test vectors for most
cryptographic algorithms, including RSA, elliptic curve crypto and
authenticated encryption. Our cryptographers have systematically surveyed the
literature and implemented most known attacks. We have over 80 test cases which
have uncovered more than [40 bugs](doc/bugs.md). For example, we found that we
could recover the private key of widely-used DSA and ECDHC implementations.

While we are committed to develop vectors for as many attacks as possible,
Project Wycheproof is by no means complete. Passing the test vectors does not
imply that the library is secure, it just means that it is not vulnerable to the
attacks that Project Wycheproof's vectors test for. Cryptographers are also
constantly discovering new attacks. Nevertheless, with Project Wycheproof
developers and users now can check their libraries against a large number of
known attacks, without having to spend years reading academic papers or become
cryptographers themselves.

For more information on the goals and strategies of Project Wycheproof, please
check out our [documentation](doc/).

### Coverage

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

The test vectors detect whether a library is vulnerable to many attacks,
including

*   Invalid curve attacks
*   Biased nonces in digital signature schemes
*   Of course, all Bleichenbacher’s attacks
*   And many more -- we have over 80 test cases

### FAQ

#### Why is the project called "Wycheproof"?

Project Wycheproof is named after 
[Mount Wycheproof](https://en.wikipedia.org/wiki/Mount_Wycheproof), the smallest
mountain in the world. The main motivation for the project at the time of its 
creation was to have a goal that is achievable. The smaller the mountain the 
more likely it is to be able to climb it.

#### Has Wycheproof testing found notable bugs?

See [docs/bugs.md](docs/bugs.md) for some notable historic bugs found using 
Wycheproof's test harnesses, or test vector data.

#### Where is the test harness code?

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

[harness-rm]: https://github.com/C2SP/wycheproof/commit/d9b8297cc998fd1a11e64cdd585a671e8923f48b
[cd27d64]: https://github.com/C2SP/wycheproof/tree/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca

### Credit

Project Wycheproof was originally created and maintained by:

*   Daniel Bleichenbacher
*   Thai Duong
*   Emilia Kasper
*   Quan Nguyen
*   Charles Lee
