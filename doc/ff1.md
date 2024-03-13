# FF1

FF1 is a format preserving encryption mode. It allows to encrypt short strings
from a given alphabet into strings of the same length using the same alphabet.
For example it can be used to encrypt strings containing decimal digits such as
'0123456789' into strings with the same format such as '8614187640'.

FF1 is an instance of FFX described in the paper *"The FFX Mode of Operation for
Format-Preserving Encryption Draft 1.1"* by M. Bellare, P. Rogaway, and T.
Spies, (Feb 20 2010)

FF1 is one of the algorithms that have been standardized in *"NIST SP 800-38G
Recommendation for Block Cipher Modes of Operation: Methods for
Format-Preserving Encryption"*
https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38g.pdf

## Authentication

Format preserving encryption is deterministic and not authenticated, which means
that it can only be used in specific scenarios.

A nice property of FF1 is that it is a strong pseudorandom permutation. Hence,
one can use the results from the paper *"Encode-then-encipher encryption: How to
exploit nonces or redundancy for efficient encryption"* by M.Bellare, P.
Rogaway: https://web.cs.ucdavis.edu/~rogaway/papers/encode.pdf Theorem 4.2 shows
that authenticity can be achieved if the messages contain sufficient redundancy.

## Available test vectors

One of the difficulties implementing FF1 is the use of integer arithmetic. The
cipher requires to handle integers up to radix<sup>m</sup>, where radix is the
size of the alphabet used to represent the plaintext and ciphertexts and where m
is about half of the size of the plaintext.

Implementations may try to avoid using BigInteger libraries, e.g., to avoid
timing leak and hence implement the necessary functions from the scratch. Doing
this can easily lead to arithmetic errors. Moreover, such bugs may only occur in
very specific cases (e.g., a specific radix and a specific radix).

A consequence of this is that Wycheproof contains significantly more test
vectors for FF1 than any other symmetric primitive. Typically, it would be a
good idea to test an implementation with test vectors that use the same radix as
a planned use case. As a result the existing test vectors try to cover common
alphabets.

## Rounding errors

Some implementations use floating point arithmetic to compute bounds. One place
where the use of floating point arithmetic can easily lead to incorrect results
is step 3 of Algorithm 7. This step computes

b = ⎡ ⎡v log<sub>2</sub>(radix)⎤/8⎤.

It is important that log<sub>2</sub>(radix) is computed without rounding errors
when radix is a power of 2. E.g., using the equivalence

log<sub>2</sub>(radix) = ln(radix) / ln(2)

easily leads to floating point values slightly bigger than the correct result.
The immediately following ceil will then round up to the next higher integer.

An example that sometimes fails is v = 29 and radix = 256. Computing v
log<sub>2</sub>(radix) as v log(radix) / log(2) using double gives v log(radix)
/ log(2) = 232.00000000000003 and b = 30 instead of the correct result b = 29.

## A proposed simplification

There are some ways to reduce the amount of integer arithmetic done during
encryption and decryption, which are described below: Section 6 of NIST
SP800-38G allows to replace the given set of steps with any mathematically
equivalent set of steps. It is indeed possible to simplify Algorithm 7
(FF1.Encrypt) and Algorithm 8 (FF1.Decrypt) a bit: NIST defines two functions
NUM<sub>radix</sub>, which converts a numeral string (i.e. list of digits) into
an integer and STR<sub>radix</sub>, which is the inverse of NUM<sub>radix</sub>:
if 0 <= x < radix<sup>m</sup> then

NUM<sub>radix</sub>(STR<sup>m</sup><sub>radix</sub>(x)) == x.

Since the variant used in FF1 uses method 2 Fig 1 of the FFX paper and also uses
blockwise addition there is no need to convert any values to a numeral string
during encryption or decryption.

Concretely, Algorithm 7 (FF1.Encrypt) is described by NIST as follows

1.  Let u = ⎣n/2⎦; v = n - u.
2.  Let A = X[1..u]; B = X[u + 1..n].
3.  Let b = ⎡ ⎡v log<sub>2</sub>(radix)⎤/8⎤.
4.  Let d = 4⎡b / 4⎤ + 4.
5.  Let P = [1]<sup>1</sup> || [2]<sup>1</sup> || [1]<sup>1</sup> ||
    [radix]<sup>3</sup> || [10]<sup>1</sup> || [u mod 256]<sup>1</sup> ||
    [n]<sup>4</sup> || [t]<sup>4</sup> .
6.  For i from 0 to 9: \
    i. Let Q = T || [0]<sup>(-t-b-1) mod 16</sup> || [i]<sup>1</sup> ||
    [NUM<sub>radix</sub>(B)]<sup>b</sup> \
    ii. Let R = PRF(P || Q). \
    iii. Let S be the first d bytes of the following string of ⎡d/16⎤ blocks: R
    || E<sub>K</sub>(R ⊕ [1]<sup>16</sup>) || E<sub>K</sub>(R ⊕
    [2]<sup>16</sup>) .. E<sub>K</sub>(R ⊕ [⎡d/16⎤-1]<sup>16</sup>). \
    iv. Let y = NUM(S). \
    v. If i is even, let m = u; else, let m = v. \
    vi. Let c = (NUM<sub>radix</sub>(A)+y) mod radix m . \
    vii. Let C = STR<sup>m</sup><sub>radix</sub>(c). \
    viii. Let A = B. \
    ix. Let B = C.
7.  Return A || B.

It can be observed that the algorithm does not make use of numeral strings other
than representing plaintext and ciphertext. Hence it is possible to describe the
same algorithm as follows (with changes highlighted):

1.  Let u = ⎣n/2⎦; v = n - u.
2.  ==Let A = NUM<sub>radix</sub>(X[1..u]); B = NUM<sub>radix</sub>(X[u +
    1..n])==
3.  Let b = ⎡ ⎡v log<sub>2</sub>(radix)⎤/8⎤.
4.  Let d = 4⎡b / 4⎤ + 4.
5.  Let P = [1]<sup>1</sup> || [2]<sup>1</sup> || [1]<sup>1</sup> ||
    [radix]<sup>3</sup> || [10]<sup>1</sup> || [u mod 256]<sup>1</sup> ||
    [n]<sup>4</sup> || [t]<sup>4</sup> .
6.  For i from 0 to 9: \
    i. Let Q = T || [0]<sup>(-t-b-1) mod 16</sup> || [i]<sup>1</sup> ||
    ==[B]<sup>b</sup>== \
    ii. Let R = PRF(P || Q). \
    iii. Let S be the first d bytes of the following string of ⎡d/16⎤ blocks: R
    || E<sub>K</sub>(R ⊕ [1]<sup>16</sup>) || E<sub>K</sub>(R ⊕
    [2]<sup>16</sup>) .. E<sub>K</sub>(R ⊕ [⎡d/16⎤-1]<sup>16</sup>). \
    iv. Let y = NUM(S). \
    v. If i is even, let m = u; else, let m = v. \
    vi. ==Let C = (A+y) mod radix<sup>m</sup> .== \
    vii. ==A = B== \
    viii. ==B = C==
7.  Return ==STR<sup>m</sup><sub>radix</sub>(A) ||
    STR<sup>m</sup><sub>radix</sub>(B)==.

This makes the code a bit faster. Additionally, it reduces the chance of faults
in the integer arithmetic during encryption and decryption.
