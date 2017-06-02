# Bugs found by Project Wycheproof
See [list of issues](issues.md) for details.

## Package OpenJDK

|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| Biased DSA,                      | Daniel Bleichenbacher      |CVE-2016-0695      | Oracle Critical Patch Update April 2016 | DsaTest: testDsaBias,                  |
: leaks signing key                :                            :                   :                                         : testBiasSha1WithDSA                    :
| GCM's timing attack,             | Quan Nguyen                |CVE-2016-3426      | Oracle Critical Patch Update April 2016 | N/A                                    |
: leaks authentication key         :                            :                   :                                         :                                        :
| GCM updateAAD                    | Quan nguyen                | N/A               | Oracle Critical Patch Update April 2016 | AesGcmTest: testLateUpdateAAD          |
| GCM wrapped around counter,      | Quan Nguyen                | N/A               | Oracle Critical Patch Update April 2016 | AesGcmTest: testWrappedAroundCounter   |
: leaks authentication key         :                            :                   :                                         :                                        :
| DSA                              | Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | DsaTest: testInvalidSignatures         |
:ArrayIndexOutOfBoundsException    :                            :                   :                                         :                                        :
|  RSA  OutOfMemoryError           | Daniel Bleichenbacher      | CVE-2016-5547     | Oracle Critical Patch Update Jan 2017   | RsaSignatureTest: testVectors          |
| DSA accepts modified signatures  | Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | DsaTest: testModifiedSignatures        |
| DSA Timing Attack                | Daniel Bleichenbacher      | CVE-2016-5548     | Oracle Critical Patch Update Jan 2017   | DsaTest: testTiming                    |
| ECDSA accepts modified signatures| Daniel Bleichenbacher      | CVE-2016-5546     | Oracle Critical Patch Update Jan 2017   | EcdsaTest: testModifiedSignatures      |
| ECDSA Timing Attack              | Daniel Bleichenbacher      | CVE-2016-5549     | Oracle Critical Patch Update Jan 2017   | EcdsaTest: testTiming                  |

## Package Conscrypt

|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| ECDH Invalid Curve Attack        | Daniel Bleichenbacher      |  N/A              |                                         | EcdhTest: multiple tests               |
| GCM IV reuse                     | Daniel Bleichenbacher      |  N/A              |                                         | AesGcmTest: testIvReuse                |
| GCM weak default tag length      | Quan Nguyen                |  N/A              |                                         | AesGcmTest:                            |
:                                  :                            :                   :                                         : testDefaultTagSizeIvParameterSpec      :


## Package BouncyCastle v1.55 and older
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| v1.55 ECDH upstream              | Daniel Bleichenbacher      |  N/A              |                                         | Ecdh: multiple tests                   |
: fix was incomplete               :                            :                   :                                         :                                        :
| ECDHC Invalid curve attack       | Daniel Bleichenbacher      |  N/A              |                                         | EcdhTest: testModifiedPublic,          |
:                                  :                            :                   :                                         : testModifiedPublicSpec, testWrongOrder :
|v1.55 PKCS #1 RSA is more         | Daniel Bleichenbacher      |  N/A              |                                         | RsaTest: testExceptions                |
: vulnerable to CCA attack         :                            :                   :                                         :                                        :
| Dhies uses unsafe ECB mode       | Daniel Bleichenbacher      | CVE-2016-1000344  |                                         | DhiesTest                              |
| ECIES use unsafe ECB mode        | Daniel Bleichenbacher      | CVE-2016-1000352  |                                         | EciesTest: testNotEcb, testDefaultEcies|
: by default for "ECIESWithAES" or :                            :                   :                                         :                                        :
: "ECIESwithDESede"                :                            :                   :                                         :                                        :
| 1.52 ECIESWithAES-CBC is         | Daniel Bleichenbacher      | CVE-2016-1000345  |                                         | EciesTest: testExceptions              |
: vulnerable to padding oracle     :                            :                   :                                         :                                        :
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
| Integer overflow, HMAC bypas     | Quan Nguyen                | CVE-2016-9123     |                                         | To be released                         |
| Accepts embedded HMAC key        | Quan Nguyen                |   N/A             |                                         | To be released                         |

## Package Go crypto
|           Summary                |            Credits         |         CVE       |       Upstream Acknowledgement          | Tests                                  |
|:---------------------------:     |:--------------------------:|:-----------------:|:--------------------------------------: |:---------------------------------------:
| GCM wrapped around counter       | Quan Nguyen                |  N/A              | https://github.com/golang/go/commit/210ac4d5e0fea2bfd4287b0865104bdaaeaffe05|    |
