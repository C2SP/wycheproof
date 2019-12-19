# Bugs found by Project Wycheproof
See [list of issues](issues.md) for details.

## Package OpenJDK

|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| Biased DSA, leaks signing key    | Daniel Bleichenbacher      |CVE-2016-0695      | Oracle Critical Patch Update April 2016 | DsaTest: testDsaBias, testBiasSha1WithDSA                    |
| GCM's timing attack, leaks auth key | Quan Nguyen                |CVE-2016-3426      | Oracle Critical Patch Update April 2016 | N/A                                    |
| GCM updateAAD                    | Quan nguyen                | N/A               | Oracle Critical Patch Update April 2016 | AesGcmTest: testLateUpdateAAD          |
| GCM wrapped around counter, leaks auth key      | Quan Nguyen                | N/A               | Oracle Critical Patch Update April 2016 | AesGcmTest: testWrappedAroundCounter    |
| DSA ArrayIndexOutOfBoundsException   | Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | DsaTest: testInvalidSignatures         |
|  RSA  OutOfMemoryError           | Daniel Bleichenbacher      | CVE-2016-5547     | Oracle Critical Patch Update Jan 2017   | RsaSignatureTest: testVectors          |
| DSA accepts modified signatures  | Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | DsaTest: testModifiedSignatures        |
| DSA Timing Attack                | Daniel Bleichenbacher      | CVE-2016-5548     | Oracle Critical Patch Update Jan 2017   | DsaTest: testTiming                    |
| ECDSA accepts modified signatures| Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | EcdsaTest: testModifiedSignatures      |
| ECDSA Timing Attack              | Daniel Bleichenbacher      | CVE-2016-5549     | Oracle Critical Patch Update Jan 2017   | EcdsaTest: testTiming                  |
| Biased ECDSA                     | Daniel Bleichenbacher      |                   |                                        | Ecdsa: testBias                        |

## Package Conscrypt

|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| ECDH Invalid Curve Attack        | Daniel Bleichenbacher      |  N/A              |                                         | EcdhTest: multiple tests               |
| GCM IV reuse                     | Daniel Bleichenbacher      |  N/A              |                                         | AesGcmTest: testIvReuse                |
| GCM weak default tag length      | Quan Nguyen                |  N/A              |                                         | AesGcmTest: testDefaultTagSizeIvParameterSpec                            |


## Package BouncyCastle v1.55 and older
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| v1.55 ECDH upstream fix was incomplete | Daniel Bleichenbacher      |  N/A              |                                         | Ecdh: multiple tests                   |
| ECDHC Invalid curve attack       | Daniel Bleichenbacher      |  N/A              |                                         | EcdhTest: testModifiedPublic,testModifiedPublicSpec, testWrongOrder          |
| v1.55 PKCS #1 RSA is more vulnerable to CCA attack | Daniel Bleichenbacher      |  N/A              |                                         | RsaTest: testExceptions                |
| Dhies uses unsafe ECB mode       | Daniel Bleichenbacher      | CVE-2016-1000344  |                                         | DhiesTest                              |
| ECIES use unsafe ECB mode by default for "ECIESWithAES" or "ECIESwithDESede"       | Daniel Bleichenbacher      | CVE-2016-1000352  |                                         | EciesTest: testNotEcb, testDefaultEcies|
| 1.52 ECIESWithAES-CBC is vulnerable to padding oracle attack         | Daniel Bleichenbacher      | CVE-2016-1000345  |                                         | EciesTest: testExceptions              |
| GCM reuses IV after doFinal()    | Daniel Bleichenbacher      | N/A               |                                         |                                        |
| ECDSA accepts invalid signatures | Daniel Bleichenbacher      | CVE-2016-1000342  |                                         | EcdsaTest: testModifiedSignatures      |
| DSA accepts invalid signatures   | Daniel Bleichenbacher      | CVE-2016-1000338  |                                         | DsaTest: testModifiedsignatures        |
| DSA generates weak key           | Daniel Bleichenbacher      | CVE-2016-1000343  |                                         | DsaTest: testKeyGeneration             |
| Allows invalid DH public key     | Daniel Bleichenbacher      | CVE-2016-1000346  |                                         | DhTest: incomplete                     |
| DSA timing attacks               | Daniel Bleichenbacher      | CVE-2016-1000341  |                                         | DsaTest: testTiming                    |
| GCM Wrapped Around Counter       | Quan Nguyen                | CVE-2015-6644     | Nexus Security Bullentin Jan 2016       | AesGcmTest: testWrappedAroundCounter   |

## Package Go JOSE (https://github.com/square/go-jose)
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| ECDH Invalid Curve Attack        | Quan Nguyen                | CVE-2016-9121     | $5500 total by Square Inc. for all bugs | To be released                         |
| Multiple signatures, auth bypass | Quan Nguyen                | CVE-2016-9122     |                                         | To be released                         |
| Integer overflow, HMAC bypass    | Quan Nguyen                | CVE-2016-9123     |                                         | To be released                         |
| Accepts embedded HMAC key        | Quan Nguyen                |   N/A             |                                         | To be released                         |

## Package Go crypto

|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| GCM wrapped around counter       | Quan Nguyen                |  N/A              |   goo.gl/OdhZcY  |
| P-384 and P-521 ScalarMult DoS   | Daniel Bleichenbacher, Harris Baskaran            | CVE-2019-6486     | [golang/go#29903](https://github.com/golang/go/issues/29903) | ecdh_secp384r1_test.json, ecdh_secp521r1_test.json |

## Package Nimbus JOSE+JWT (https://connect2id.com/products/nimbus-jose-jwt)
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| CBC-HMAC is vulnerable to padding oracle attack  | Quan Nguyen                |  N/A              |   https://goo.gl/ACZQeI  | To be released
| CBC-HMAC integer overflow, HMAC bypass  | Quan Nguyen                |  N/A              |   https://goo.gl/ACZQeI  | To be released

## Package OpenSSL
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| X25519 incorrect carry handling | Alex Gaynor and Paul Kehrer | N/A | https://github.com/openssl/openssl/issues/6687 |
| Ed25519 malleable signatures    | Paul Kehrer and Alex Gaynor | N/A | https://github.com/openssl/openssl/issues/7693 |

## Package LibreSSL
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| Overly lax RSA PKCS1v1.5 parsing | Alex Gaynor and Paul Kehrer | N/A | [link](https://github.com/openbsd/src/commit/4698a0ba0d5547fce37134cb00f204c68f429885#diff-8c6377c3026df41da690063739326043) |
