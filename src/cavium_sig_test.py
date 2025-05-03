# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asn
import asn_parser
import base64

Test = lambda **args: args
TESTS = [
    Test(
        key_id="keyid_e1738821",
        id="keyid_bdfb3c62",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIQD5Op7nXTrYYjtyQQ4cyXp7Xu0/5bxgWlPmdS8MRcwUqQIgHuy"
        "lAAvl+omw4ywqkEBBN6zy/TcohZ/2qABIod8fsw8=",
        passed=True),
    Test(
        id="keyid_1df66a43",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEYCIQDBnmfg+7q2ANG/E9GSyXVidPpdAD0qSpD6d/cvSIy1WQIhAMi"
        "vTipVaq2p+BKfiG+QTOjIvv5f9Fp+TY4aComtQLjY",
        passed=False),
    Test(
        key_id="keyid_39f2cae4",
        id="keyid_ec89a9a6",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCICso1GTo2M+T6Zaj0Ax37eGrwpA9HCoFPvYWP347LuswAiEA5p2"
        "ff+eAHUcYyU3Q21bjP/WmMgEko9n3lyTGSrauSy0=",
        passed=False),
    Test(
        key_id="keyid_3b0607b7",
        id="keyid_4d5770f7",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIQDhEu1ESQsrYQwWSUd4ZO/NOdxW7pUcBnyWd8V71pF7eQIgFjV"
        "+6Z6RBnmSGkRnNdqsVBZkc7uJAXSDlmzBJ6RUUgo=",
        passed=True),
    Test(
        key_id="keyid_be29c1ce",
        id="keyid_29a357b9",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIEqawXYLK/d9cnD3Rug/HHHHL/hPjMo+FZNfy+h1QO1tAiEA1bK"
        "fZS/2GANhCuBF/GEInmXDHjLe8zP0SqUiCaZiYjY=",
        passed=False),
    Test(
        key_id="keyid_850448ed",
        id="keyid_aec5bd12",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEQCIBE5oIor7xqeyS3RpLMlSvWya2zZWGtgSysAMOd1KQilAiB0Wce"
        "oFnYRhfs5pWyuRi7v4+zYp6hIvbFKY2DOmUu8dQ==",
        passed=False),
    Test(
        key_id="keyid_3685c7f0",
        id="keyid_dafc6510",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIF6fWxHqx79dkxGH81oUqgRoVm4QTnwIvXriOAqviYWDAiEAob0"
        "SBAvgB7pHt4eHH1dSYgDOx3szu51Za0L0t2Q4VKg=",
        passed=False),
    Test(
        key_id="keyid_af7317f1",
        id="keyid_6861a4ef",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEQCIA9mKB6cUuMqIHalaZ1qcAmx+CGBPvzRerd5QP8iz95RAiBefhA"
        "bMhP59Cz80oI6DMw9vIjrHM8yttV82kwnGN/wkQ==",
        passed=True),
    Test(
        key_id="keyid_57dc8e7b",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEQCIFCMsKrMRu0cILUr8OFf/hiVKBL335y+dOFHI+7sPhpnAiB1dlR"
        "O6709R1MTFXiOGUslXXJOgQTWWap0uYOGppRk7Q==",
        passed=True),
    Test(
        key_id="keyid_a8e95170",
        id="keyid_1eba5003",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIBiWRRA6sYvpqPcZwxWqVpoaQUwA0BNZfG/c9OqWLIAqAiEAtX5"
        "91b5mElZauzO014b/9QXsEK1eF+ctStpxaK57LXs=",
        passed=False),
    Test(
        key_id="keyid_b70ea85c",
        id="keyid_ab17049e",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIQDALdL+i3VrN1v3dYZXIbX1M65P7FcmbiQkhAaaiDzHKAIgN+l"
        "8uykKOdEjQyfEy36Wza/F1lYFajeY3HeR+F/ZJf0=",
        passed=True),
    Test(
        key_id="keyid_7697a645",
        id="keyid_a3538be4",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIQC8jFpEUHD0U+Cb2ZcfypdwIpJ90JLvS4TsPRj7yB2CUgIgSFm"
        "fLgxdB5aHX0neOl6E1BVFm+eukGzz2XoCb6lkE60=",
        passed=True),
    Test(
        key_id="keyid_9e5aad03",
        id="keyid_0633398b",
        digest="GED6zs//Se+mWs8aYtcFY8PEy9qWZqKEg/XpghD5itU=",
        signature="MEUCIChjjL1CgYlXYgztO+P9qtrTaJQ6ff8NKvHu2raq/HKHAiEAy9I"
        "os0IpH6xPJHgYdJTzctNocm28hH6h0grSUrL3kbY=",
        passed=False),
]


def test():
  for t in TESTS:
    sig_bytes = base64.b64decode(t["signature"])
    r, s = asn_parser.parse(sig_bytes)
    print(s.bit_length(), t["passed"])
    # n is somewhere close to 2**256. So the following should be true in
    # almost all cases.
    assert r > 0 and r < 2**256
    assert s > 0 and s < 2**256
    assert t["passed"] == (s.bit_length() == 256)
    # Checks that the signatures are DER encoded
    assert asn.encode([r, s]) == sig_bytes


if __name__ == "__main__":
  test()
