# References

<!-- Format for references:
The labels used in this file are not final. Hence thrid parties should not refer
to them.

Unfortunately there seems to be no simple way to manage references in markdown.
This file is an attempt to add a bibliography. Because of the lack of tools it
is necessary to define some simple formats, with the idea that reformatting at
a later point becomes easy.

RFCs: RFCs are supported. A text like RFC 2785 automatically generates a link.
Hence RFCs are not listed in this bibliography.

CVEs: CVEs use a label CVE-xxxx-yyyy. The description of CVEs is often short
and sometimes misleading. Additional information is often difficult to find.
Hence the CVE entry here will often contain some additional descriptions.

Papers:
Because of the restrictions of markdown Papers use a section header to allow
references. To allow future reformatting paper references use the following
lines:
line 1: authors (comma separated)
line 2: "title"
line 3: publication, pages
line 4: link
Additional information is added as a separate paragraph.
-->

<!-- mdformat off see above -->
<!-- papers -->


### AES-GCM
D. A. McGrew and J. Viega,
"The Galois/Counter Mode of operation (GCM).",
http://csrc.nist.gov/CryptoToolkit/modes/proposedmodes/gcm/gcm-spec.pdf.

### AbVaLo19
R. Abarzúa, C. Valencia and J. López,
"Survey for Performance & Security Problems of Passive Side-channel Attacks Countermeasures in ECC",
https://eprint.iacr.org/2019/010.pdf

### ABMSV03
A. Antipa, D. Brown, A. Menezes, R. Struik, S. Vanstone,
"Validation of Elliptic Curve Public Keys",
PKC 2003,
https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf

### AkiTak03
T. Akishita, T. Takagi,
"Zero-Value Point Attacks on Elliptic Curve Cryptosystem",
ISC 2003, pp. 218-233.
https://www-old.cdc.informatik.tu-darmstadt.de/reports/TR/TI-03-01.zvp.pdf

### BeMeMu00
I. Biehl, B. Meyer, V. Müller,
"Differential Fault Attacks on Elliptic Curve Cryptosystems",
Crypto '00, pp. 131-164

### BelRog00
Bellare, Rogaway,
"Encode-Then-Encipher Encryption: How to exploit nonces or redundancy in plaintexts for efficient cryptography",
Asiacrypt 2000, pp.317--330.

### FGHT16
J. Fried, P. Gaudry, N. Heininger, E. Thome,
"A kilobit hidden SNFS discrete logarithm computation".
http://eprint.iacr.org/2016/961.pdf

### Goubin03
L. Goubin,
"A Refined Power-Analysis Attack on Elliptic Curve Cryptosystems",
PKC’03, pp. 199–210,
https://www.iacr.org/archive/pkc2003/25670199/25670199.pdf

### Gordon92
D. M. Gordon.
"Designing and detecting trapdoors for discrete log cryptosystems."
CRYPTO’92, pp. 66–75.

### GPPT16
D. Genkin, L. Pachmanov, I. Pipman, E. Tromer,
"ECDH Key-Extraction via Low-Bandwidth Electromagnetic Attacks on PCs",
http://cs.tau.ac.il/~tromer/papers/ecdh.pdf

### LimLee98
C.H. Lim and P.J. Lee,
"A key recovery attack on discrete log-based schemes using a prime order subgroup",
CRYPTO' 98, pp 249--263.

### Joux-Gcm
A. Joux,
"Authentication failures in NIST version of GCM",
http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/800-38_Series-Drafts/GCM/Joux_comments.pdf.

### Ferguson05
N. Ferguson,
"Authentication weaknesses in GCM",
https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf

### HowSma99
N.A. Howgrave-Graham, N.P. Smart,
"Lattice Attacks on Digital Signature Schemes"
http://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf

### Krawczyk10
H. Krawczyk,
"Cryptographic extraction and key derivation: the HKDF scheme",
https://eprint.iacr.org/2010/264.pdf

### Nguyen04
P. Nguyen,
“Can we trust cryptographic software? Cryptographic flaws in Gnu privacy guard 1.2.3”,
Eurocrypt 2004,
https://www.iacr.org/archive/eurocrypt2004/30270550/ProcEC04.pdf

### Odlyzko90
A. M. Odlyzko,
"The rise and fall of knapsack cryptosystems",
Cryptology and Computational Number Theory, pp.75-88, 1990

### OorWie96
P. C. van Oorschot, M. J. Wiener,
"On Diffie-Hellman key agreement with short exponents",
Eurocrypt 96, pp 332--343.

### WeakDh
D. Adrian et al.
"Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice"
CCS '15 pp 5--17.
https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf

A good analysis of various DH implementations. Some misconfigurations pointed
out in the paper are: p is composite, p-1 contains no large prime factor, q is
used instead of the generator g.

### Eurocrypt92 panel
"The Eurocrypt'92 Controversial Issue Trapdoor Primes and Moduli",
EUROCRYPT '92, LNCS 658, pp. 194-199.

### Bleich98
D. Bleichenbacher,
"Chosen ciphertext attacks against protocols based on the RSA encryption standard PKCS# 1",
Crypto 98.

### Manger01
J. Manger,
"A chosen ciphertext attack on RSA optimal asymmetric encryption padding (OAEP) as standardized in PKCS# 1 v2.0",
Crypto 2001.

This paper shows that OAEP is susceptible to a chosen ciphertext attack if error
messages distinguish between different failure condidtions.

### Smart10
N. Smart,
"Errors matter: Breaking RSA-based PIN encryption with thirty ciphertext validity queries",
RSA conference, 2010.

This paper shows that padding oracle attacks can be successful with even a small number
of queries.

### KlPoRo03
V. Klima, O. Pokorny, and T. Rosa,
"Attacking RSA-based Sessions in SSL/TLS",
https://eprint.iacr.org/2003/052/

### BFKLSST12
R. Bardou, R. Focardi, Y. Kawamoto, L. Simionato, G. Steel, J.K. Tsay,
"Efficient padding oracle attacks on cryptographic hardware"
Crypto 2012

### ECRYPT-II
Yearly Report on Algorithms and Keysizes (2011-2012),
http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf

<!-- standards -->
### NIST-SP800-38d
"Recommendation for block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC",
http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

### NIST-SP800-56A
NIST SP 800-56A, revision 2, May 2013.
http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf

### NIST-SP800-57
http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf

### NIST SP800-131A
Transitioning the Use of Cryptographic Algorithms and Key Lengths
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
Some notable changes in revision 2: Keys with less than 112 bit security are now
disallowed. EdDSA will be added with FIPS 186-5. TDES is disallowed after 2023.
RSA PKCS 1 v.1.5 for encryption is disallowed after 2023.

### EnisaKeySize14
Enisa,
"Algorithms, key size and parameters report – 2014"
https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014

<!-- use first label for refs depending on the version -->
### FIPS-186-4
National Institute of Standards and Technology,
"Digital Signature Standard (DSS)",
July 2013.
http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

### PKCS-3
"PKCS #3, Diffie–Hellman Key Agreement".
http://uk.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-3-diffie-hellman-key-agreement-standar.htm

<!-- CVEs -->
### CVE-1999-1444
Alibaba 2.0 generated RSA key pairs with an exponent 1

### CVE-2012-5081
Java JSSE provider leaked information through exceptions and
timing. Both the PKCS #1 padding and the OAEP padding were broken:
http://www-brs.ub.ruhr-uni-bochum.de/netahtml/HSS/Diss/MeyerChristopher/diss.pdf

### CVE-2015-6924
Utimaco HSMs vulnerable to invalid curve attacks.

### CVE-2015-7940
The Bouncy Castle Java library before 1.51 does not validate a point is on the
elliptic curve, allowing an "invalid curve attack".

### CVE-2015-7827

### CVE-2016-9121
go-jose before 1.0.4 suffers from an invalid curve attack for the ECDH-ES algorithm.

### CVE-2017-7781
Issue with elliptic curve addition in mixed Jacobian-affine
coordinates. Firefox and Java suffered from a bug where adding
a point to itself resulted in the point at infinity.

### CVE-2017-16007
node-jose earlier than version 0.9.3 is vulnerable to an
invalid curve attack.

### CVE-2018-2972
The AES-GCM implementation in jdk9 handled CTR overflows
incorrectly.

### CVE-2018-5383
Bluetooth implementations may not sufficiently validate
elliptic curve parameters during Diffie-Hellman key exchange
http://www.cs.technion.ac.il/~biham/BT/

### CVE-2019-6486
golang/elliptic ECDH has an arithmetic error that allows to find private keys
with an adaptive chosen message attack.

<!-- mdformat on -->

