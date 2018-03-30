# Project Wycheproof

This page describes the goals and strategies of project Wycheproof. See
[README](../README.md) for an introduction to the project.

## Defense in depth

There are a number of tests where we check for expected behaviour
rather than exploitability. Examples:

* default values: we expect that default values are reasonable and correspond
  to recommendations by current standards. Concretely, in 2016 it is not OK
  if an RSA key generation uses 1024 bits as default or digital signatures
  use SHA-1 as default.
* timing attacks: any timing that relation between keys (or other sensitive)
  data and the measured time fails the test. However tests are set up
  such that too much noise during the test can prevent that a relation
  is detected.
* wrong exceptions: The JCE interface often specifies the exceptions that
  should be thrown when the input is invalid. We expect the specified
  exceptions in the tests.
* leaking information through exceptions: While it is a good practice to not
  return detailed logs to a sender, we consider text in exceptions as
  information that a potential attacker can learn. For example padding
  failures during decryption should not contain information about the
  reason why a decryption failed.
* RSA PKCS #1 signatures: If a signature verification allows signatures
  with lots of modifications, then RSA signatures can be forged for small
  public exponents. Tests do not measure how many bytes can be modified.
  Any accepted modification of the PKCS #1 padding fails the test.

## Compatibility between providers

One of the goals of Wycheproof is to test for compatibility issues.
Switching JCE providers should not introduce vulnerabilities simply because
the solution was developed by another provider.

An example for this was the following observation: When using AES-GCM then
javax.crypto.CipherInputStream worked sort of with JCE and
org.bouncycastle.jcajce.io.CipherInputStream.java worked with BouncyCastle.
However, authentication was skipped in some cases when
javax.crypto.CipherInputStream was used with BouncyCastle.

## Comparing cryptographic libraries is not a primary goal

Because of the strategies mentioned above we expect that a comparison of
cryptographic libraries based on the bugs found would be biased:

* Libraries used internally in Google get more attention.
  Serious vulnerabilities in these libraries should be fixed at the time the
  tests are added to Wycheproof.  On the other hand it is also likely that
  tests find a larger number of bugs in these libraries when old versions are
  tested.
* Tests often check for expected behaviour and compatibility.
  Expected behaviour is often defined by a prominent library.
  Pointing out such problems can therefore penalize smaller third party
  libraries.
* We are working toward covering as many potential vulnerabilities as possible
  with test vectors, because this simplifies porting the tests to other
  languages or interfaces. Thus a single test case can cover multiple
  vulnerabilities.

We are not trying to remove this bias when this interferes with more important
goals such as early reporting.
Hence we are reluctant to publish comparisons.


## Thoughts on the design of cryptographic libraries

We should promote robust interfaces with the goal to simplify
the use of the library, code reviews of applications using the
library and testing the library.

* When cryptographic primitives require randomness then the random
  numbers should be chosen by the library. It shouldn't be possible
  for a user to provide randomness. If the library itself chooses the
  randomness then it is possible (at least to some degree) to check
  that the random number generation is appropriate for the primitive.
  If the user can provide the randomness then it is not possible to
  catch this in our tests.
