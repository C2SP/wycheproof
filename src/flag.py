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

import dataclasses
import enum
from typing import Optional, Any


class BugType(enum.Enum):

  # A test vector that contains a basic test vector.
  # The test vector tries to avoid any special cases.
  # If such test vectors fail, then this should typically
  # indicate that the primitive by itself is not supported or that
  # the test or the provider are incompatible or misconfigured.
  #
  # Failing a basic test should probably not trigger a bug report.
  BASIC = enum.auto()

  # A test vector with an invalid authentication.
  #
  # Failing such a test vector does not necessarily indicate a
  # vulnerability, but it indicates a bug that needs attention
  # and likely should be fixed.
  AUTH_BYPASS = enum.auto()

  # Key material or plaintext may be leaked.
  #
  # Failing such a test vector does not necessarily indicate a
  # vulnerability, but it is typically a bug that should be fixed.
  CONFIDENTIALITY = enum.auto()

  # A test vector that checks for legacy behaviour.
  # Sometimes libarires accept slightly wrong formats.
  #
  # Failing such a test vector should not trigger a bug report.
  LEGACY = enum.auto()

  # Some functionality may not be implemented.
  #
  # Many implementations limit parameters. E.g., they may not
  # implement infrequently used key sizes or restrict input sizes.
  # An example is AES_WRAP, where wrapping a key smaller than
  # 16 bytes is a special case that may not be implemented.
  #
  # Failing such a test vector should not trigger a bug report.
  FUNCTIONALITY = enum.auto()

  # The test vector uses parameters that are below NIST recommendation
  # (e.g. below 112-bit). Frequently libraries reject keys using such weak
  # parameters.
  #
  # Failing such a test vector should not trigger a bug report.
  # Test vectors with weak parameters are often marked as 'acceptable'
  # instead of 'valid'.
  WEAK_PARAMS = enum.auto()

  # A bug that may be a sign of a real vulnerability. A typical case is
  # RSA PKCS#1 signatures, where the verification of the padding uses
  # a sloppy DER parsers. Accepting a few alternative BER encodings is
  # a bug that may not be exploitable. However, the verification method
  # is bad practice and much too often includes additional bugs that are
  # a vulnerability.
  #
  # Failing such a test vector might mean that it would be a good idea
  # to analyze the failure. Even if the bug is not a vulnerability
  # a bug report might make sense.
  CAN_OF_WORMS = enum.auto()

  # The ciphertext or (ephemeral) keys are malleable.
  # A ciphertext or (ephemeral) keys can be modified without changing
  # the value of the plaintext / key (i.e. this type of bug is sometimes
  # described as benign malleability).
  # While such bugs are frequently indeed benign, it may be used in
  # some situation to watermark message.
  #
  # Bug reports should explain the issue.
  MALLEABILITY = enum.auto()

  # A BER encoding is used in a place where DER encoding is expected.
  # This bug type is being used in situations, where a BER encoding
  # does not lead to severe bugs, but where CVEs are issued.
  # Examples are ECDSA or DSA signatures.
  BER_ENCODING = enum.auto()

  # A signature that is slightly malleable. The modification of the
  # signature does not change the message that was signed.
  # While such bugs are frequently benign, they may be a vulnerability,
  # where a protocol assumes that signatures are unique.
  #
  # Bug reports with an explanation of signature malleability would
  # make sense.
  SIGNATURE_MALLEABILITY = enum.auto()

  # There are test vectors that specifically constructed to cover
  # edge cases. For example it is possible to find keys and messages
  # such that there is a valid signature (r, s) where both r and s
  # are small integers. Failing to accept edge cases indicates a bug
  # in the implementation.
  # When edge cases fail, then it is often unclear how serious the
  # bug is. The main question often is whether an attacker can construct
  # inputs that trigger the faulty edge cases and thereby gain information.
  #
  # Analyzing the bug might make sense.
  EDGE_CASE = enum.auto()

  # There are test vectors that have been constructed by skipping
  # a step in the implementation. Such steps can for example include
  # a truncation or a modular reduction.
  # Test vectors with this bug type typically point to an incompatible
  # implementation. This bug type should only be used if a vulnerability
  # is rather unlikely.
  MISSING_STEP = enum.auto()

  # This is a test vector specifically generated to detect a CVE or
  # a known bug.
  #
  # Bug reports are relatively easy to make, since it is possible to
  # explain the motivation for the bug report.
  KNOWN_BUG = enum.auto()

  # The implementation accepts additional primitives.
  # An example are signatures verifications that accept multiple hashes.
  # An attacker could for example target the weakest hash.
  WRONG_PRIMITIVE = enum.auto()

  # A parameter has been modified. Typically we expect that cryptographic
  # primitives perform sufficient parameter checks and detect modified
  # parameters.
  # The severity of such bugs depends on the situation.
  # Example: EC key with modified cofactor.
  MODIFIED_PARAMETER = enum.auto()

  # Defined behavior for edge cases that should not happend.
  # E.g. Xdh defines a shared secret for points on the twist.
  # The expectation is that a library either reject such edge cases
  # or implements them according to expectation.
  DEFINED = enum.auto()
  # TODO: deprecate. Ideally each test vector should have
  #   some description and bug type
  UNKNOWN = enum.auto()

@dataclasses.dataclass
class Flag:
  label: str  # The preferred label used for the flag
  description: str  # a description of the flag
  bug_type: BugType = BugType.UNKNOWN  # a value of the enum above
  effect: str = "" # Potential effects.

  # Links to additional information. There is no guarantee that these
  # links give useful information.
  links: Optional[list[str]] = None

  # A list of CVEs with potentially related bugs.
  # It should be noted that it is very difficult to assess the
  # vulnerability of a bug without analyzing the bug in detail.
  # Hence these CVEs may give additional information or they may be
  # completely unrelated.
  cves: Optional[list[str]] = None

  schema = {
    "description" : {
        "type" : str,
        "desc" : "A description of the flag",
    },
    "bugType" : {
        "type" : str,
        "desc" : "The type of the bug"
    },
    "effect" : {
        "type" : str,
        "desc" : "A description of potential effects of the bug"
    },
    "links" : {
        "type" : list[str],
        "desc" : "A list of references",
    },
    "cves" : {
        "type" : list[str],
        "desc" : "A list of potentially related CVEs"
    },
  }
  def json(self) -> dict[str, Any]:
    """Returns this flag as a JSON structure."""
    res = dict()
    res["bugType"] = self.bug_type.name
    if self.description:
      res["description"] = self.description
    if self.effect:
      res["effect"] = self.effect
    if self.links:
      res["links"] = self.links
    if self.cves:
      res["cves"] = self.cves
    return res


def Cve(cve: str,
        description: str,
        effect: str = "",
        *,
        bug_type: BugType = BugType.KNOWN_BUG,
        links: Optional[list[str]] = None,
        cves: Optional[list[str]] = None) -> Flag:
  if cves is None:
    cves = [cve]
  return Flag(
      cve,
      description,
      effect=effect,
      bug_type=bug_type,
      links=links,
      cves=cves)


# Just some predefined flags:
NORMAL = Flag(
    label="Normal",
    bug_type=BugType.BASIC,
    description="The test vector contains a pseudorandomly generated, valid "
    "test case. Implementations are expected to pass this test.")
