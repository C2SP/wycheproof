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

import flag
import asn
import special_int
import prand
import group as gp
from collections.abc import Iterator

# (r, s, comment, flags)
ModifiedSignatures = Iterator[tuple[int, int, str, list[flag.Flag]]]

def modify_rs(group, r: int, s: int) -> ModifiedSignatures:
    """Generates signatures with modified values for r and s.

    An ECDSA signature is only valid if 0 < r < n and 0 < s < n.
    This method generates invalid signatures that might get accepted if
    the range check is omitted.

    Args:
      key_pair: a key pair (private key may be None)
      msg: the message to sign
      r: the r value of a valid signature for msg
      s: the s value of a valid signature for msg
    Yields: tuples (r, s, description, flags)
    """

    range_check_flag = flag.Flag(
        label="RangeCheck",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified. By adding or subtracting the order of the group (or "
        "other values) the test vector checks whether signature "
        "verification verifies the range of r and s.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")
    modified_int_flag = flag.Flag(
        label="ModifiedInteger",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified. The goal is to check for arithmetic errors.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")
    integer_overflow_flag = flag.Flag(
        label="IntegerOverflow",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains an r and s that has been "
        "modified, so that the original value is restored if the "
        "implementation ignores the most significant bits.",
        effect="Without further analysis it is unclear if the modification "
        "can be used to forge signatures.")

    n = group.n
    bits = n.bit_length()
    for cflag, val, desc in [
        (range_check_flag, r + n, "r + n"),
        (range_check_flag, r - n, "r - n"),
        (range_check_flag, r + 256 * n, "r + 256 * n"),
        (modified_int_flag, -r, "-r"),
        (modified_int_flag, n - r, "n - r"),
        (modified_int_flag, -n - r, "-n - r"),
        (integer_overflow_flag, r + 2**bits, f"r + 2**{bits}"),
        (integer_overflow_flag, r - 2**bits, f"r - 2**{bits}"),
        (integer_overflow_flag, r + 2**(64 + bits), f"r + 2**{64 + bits}"),
    ]:
      yield val, s, f"replaced r by {desc}", [cflag]

    for cflag, val, desc in [
        (range_check_flag, s + n, "s + n"),
        (range_check_flag, s - n, "s - n"),
        (range_check_flag, s + 256 * n, "s + 256 * n"),
        (modified_int_flag, -s, "-s"),
        (modified_int_flag, -n - s, "-n - s"),
        (integer_overflow_flag, s + 2**bits, f"s + 2**{bits}"),
        (integer_overflow_flag, s - 2**bits, f"s - 2**{bits}"),
        (integer_overflow_flag, s + 2**(64 + bits), f"s + 2**{64 + bits}"),
    ]:
      yield r, val, f"replaced s by {desc}", [cflag]


def generate_fake_sigs(group) -> ModifiedSignatures:
    """Generates edge case signatures with unusual values for r and s.

    This method tries silly edge cases such as r=0 and s=0. Careless coding
    such as returning 0 for the modular inverse of 0 could allow forgeries
    with such values.
    """
    invalid_sig_flag = flag.Flag(
        label="InvalidSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The signature contains special case values such as r=0 "
        "and s=0. Buggy implementations may accept such values, if the "
        "implementation does not check boundaries and computes s^(-1) == 0.",
        effect="Accepting such signatures can have the effect that an "
        "adversary can forge signatures without even knowning the message "
        "to sign.",
        cves=[
            "CVE-2022-21449",  # psychic signatures
            "CVE-2021-43572",  # Stark Bank Crypto
            "CVE-2022-24884",  # ecdsautils
        ],
    )
    n = group.n
    p = group.field_size()
    vals = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (n, "n"),
        (n - 1, "n - 1"),
        (n + 1, "n + 1"),
        (p, "p"),
        (p + 1, "p + 1"),
    ]
    for r, rtxt in vals:
      for s, stxt in vals:
        comment = f"Signature with special case values r={rtxt} and s={stxt}"
        yield r, s, comment, [invalid_sig_flag]

def generate_wrong_types(group) -> ModifiedSignatures:
    invalid_types_flag = flag.Flag(
        label="InvalidTypesInSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The signature contains invalid types. "
        "Dynamic typed languages sometime coerce such values of different "
        "types into integers. If an implementation is careless and has "
        "additional bugs, such as not checking integer boundaries then "
        "it may be possible that such signatures are accepted.",
        effect="Accepting such signatures can have the effect that an "
        "adversary can forge signatures without even knowning the message "
        "to sign.",
        cves=[
            "CVE-2022-21449",  # psychic signatures
        ],
    )
    n = group.n
    p = group.field_size()
    smallSet = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (n, "n"),
        (p, "p"),
    ]
    wrong_types = [
        (0.25, "0.25"),
        (float("nan"), "nan"),
        (True, "True"),
        (False, "False"),
        (asn.Null(), "Null"),
        (asn.Utf8String(""), "empyt UTF-8 string"),
        (asn.Utf8String("0"), '"0"'),
        ([], "empty list"),
        ([0], "list containing 0"),
    ]
    for r, rtxt in smallSet:
      for s, stxt in wrong_types:
        comment = f"Signature encoding contains incorrect types: r={rtxt}, s={stxt}"
        yield r, s, comment, [invalid_types_flag]

    for x, xtxt in wrong_types:
      comment = f"Signature encoding contains incorrect types: r={xtxt}, s={xtxt}"
      yield x, x, comment, [invalid_types_flag]
      
    for r, rtxt in wrong_types:
      comment = f"Signature encoding contains incorrect types: r={rtxt}, s=0"
      yield r, 0, comment, [invalid_types_flag]

def point_from_x(group, x: int) -> gp.Point:
    y = group.get_y(x)
    if y is not None:
      return group.get_point(x, y)


def generate_edge_case_signatures(group, truncated_hash: int
    ) -> Iterator[tuple[gp.Point, int, int, str, list[flag.Flag]]]:

    """Generates edge case signatures.

    This method generates signatures that trigger an edge case during
    signature verification. Such edge cases are for example, encountering
    the point at infinity, adding two points of equal value, small or special
    case integers that could trigger arithmetic overflows. Such edge cases
    typically are constructed by selecting the public key depending on the
    values of the signature. This unfortunately prevents generating such
    edge cases for the self signed signatures used to test implementations
    of AMD_SEV.

    Args:
      group: the EC group used for the signature
      truncated_hash: the truncated hash of the message to sign.
    Yields: tuples of the form (pt, r, s, comment, flags), where
      pt is the intermediate point R, that is obtained during verification.
      
    """

    def next_point_from_x(x: int,
                        delta: int = 1,
                        in_subgroup: bool = True) -> tuple[int, gp.Point]:
     """Finds a point on the curve with x-coordinate x + k*delta

      Args:
         x: the first x-coordinate tried
         delta: the increment
         in_subgroup: point must be subgroup of order n

      Returns:
         a tuple containing the x-coordinate and corresponding point on the
         curve
      """
     if delta == 0:
        raise ValueError("delta must not be 0")
     q = group.field_size()
     while True:
      x %= q
      y = group.get_y(x)
      if y is not None:
        pt = group.get_point(x, y)
        if group.h == 1 or not in_subgroup or not pt * group.n:
          return x, pt
      x += delta


    # This function is skipped if h is large.
    # In particular this only happens for binary curves that are unimportant.
    if group.h > 4:
      return

    flag_small_rs = flag.Flag(
        label="SmallRandS",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vectors contains a signature where both r and s "
        "are small integers. Some libraries cannot verify such signatures.",
        effect="While the signature in this test vector is constructed and "
        "similar cases are unlikely to occur, it is important to determine "
        "if the underlying arithmetic error can be used to forge signatures.",
        cves=["2020-13895"])
    flag_modular_inverse = flag.Flag(
        label="ModularInverse",
        bug_type=flag.BugType.EDGE_CASE,
        description="The test vectors contains a signature where computing "
        "the modular inverse of s hits an edge case.",
        effect="While the signature in this test vector is constructed and "
        "similar cases are unlikely to occur, it is important to determine "
        "if the underlying arithmetic error can be used to forge signatures.",
        cves=["CVE-2019-0865"])
    e = truncated_hash
    n = group.n
    p = group.field_size()

    s = n - 3
    x, pt = next_point_from_x(p - 1, -1)
    yield pt, x % n, s, "k*G has a large x-coordinate", []

    # This gives the same public key as the group before and could be merged.
    yield pt, x, s, "r too large", []

    r, pt = next_point_from_x(n - 1, -1)
    yield pt, r, r - 1, "r,s are large", []

    r, pt = next_point_from_x(2**(n.bit_length() - 1) - 1, -1)
    for t in [r, r-1]:
      s = pow(t, -1, n)
      yield pt, r, s, "r and s^-1 have a large Hamming weight", []

    # Test vectors where r and s, or s^-1 are small.
    # SunEC fails over NIST-P224 for several of the test vectors.
    # uECC fails for r=5, s=3.
    # CVE-2020-13895 Perl ECDSA fails for small r and s and s == 1
    # CVE-2020-12607 signature verification fails for extreme k and s^-1
    r = 0
    for _ in range(2):
      r, pt = next_point_from_x(r + 1)
      for s in sorted({1, 3, r, r + 1}):
        yield pt, r, s, "small r and s", [flag_small_rs]

    yield pt, r + n, s, "r is larger than n", []
    yield pt, r, 1234567 + n, "s is larger than n", []
    r, pt = next_point_from_x(256)
    yield pt, r, pow(127, -1, n), "small r and s^-1", []
    r, pt = next_point_from_x(12837129847132876)
    s = pow(182319823181923141, -1, n)
    yield pt, r, s, "smallish r and s^-1", []

    # uECC fails for the following test vector
    r, pt = next_point_from_x(1283712984713287618231982313211)
    s = pow(257, -1, n)
    yield pt, r, s, "100-bit r and small s^-1", []

    r, pt = next_point_from_x(256)
    s = pow(335576113200219857839687952955, -1, n)
    yield pt, r, s, "small r and 100 bit s^-1", []

    r, pt = next_point_from_x(486861910918697195699085147172)
    s = pow(335576113200219857839687952955, -1, n)
    yield pt, r, s, "100-bit r and s^-1", []

    r, pt = next_point_from_x(n - 128)
    s = pow(n - 3, -1, n)
    yield pt, r, s, "r and s^-1 are close to n", []

    for r0, s in [
        (11260405065460177229, 9484249322280366187),
        (782237152301174935240475920333, 1252996219030822393373754006666),
        (183898464772630595985352006549717268090,
         176736452780547087482338089615226438847),
        (973002014391743892082692660319135235850587868127,
         1293610153025254189261438125895338053927928184761),
    ]:
      r, pt = next_point_from_x(r0)
      size = max(r, s).bit_length()
      yield pt, r, s, f"r and s are {size}-bit integer", []

    r, pt = next_point_from_x(n // 3)
    yield pt, r, 1, "s == 1", []
    yield pt, r, 0, "s == 0", []

    for s in special_int.edge_case_inverse(n):
      yield pt, r, s, "edge case modular inverse", [flag_modular_inverse]

    # extreme values for u1 and u2
    r, pt = next_point_from_x(n // 3, -1)
    yield pt, r, e, "u1 == 1", []
    yield pt, r, -e % n, "u1 == n - 1", []  # uEcc fails for this
    yield pt, r, r, "u2 == 1", []
    yield pt, r, -r % n, "u2 == n - 1", []  # uEcc fails for this

    # edge cases for u1 and u2
    uset = {3,
           2**n.bit_length(),
           2**(n.bit_length() - 1),
           2**(n.bit_length() - 1) - 1,
           n - 3,
           n - 2**32,
           n - 2**51,
           n - 2**52,
           n - 2**64,
           }
    for i in range(1,7):
      uset.add(n - 2 * (-n % 2**i))

    r, pt = next_point_from_x(2**(n.bit_length() - 1) - 3, -1)
    for u1 in sorted(uset):
      s = e * pow(u1, -1, n) % n
      yield pt, r, s, "edge case for u1", []

    for u2 in sorted(uset):
      s = r * pow(u2, -1, n) % n
      yield pt, r, s, "edge case for u2", []


    # If there is a point with x-coordinate 0 on the curve then generate
    # signatures with this point as indermediate result.
    pt = point_from_x(group, 0)
    if pt:
      yield pt,  1, n // 3, "point with x-coordinate 0", []
      yield pt,  2**n.bit_length(), n // 5, "point with x-coordinate 0", []

    # pt and hence k are edgecases.
    # The first case triggered b/74209208.
    # Additional cases are generated just to check if the edgecase s
    # is triggering the problem.
    for pt in [2 * group.generator(), -group.generator()]:
      r = int(pt.affine_x()) % n
      s = n // 3
      yield pt, r, s, "extreme value for k and edgecase s", []
      for invs in (-7, -5, 5, 7):
        s = pow(invs, -1, n)
        yield pt, r, s, "extreme value for k and s^-1", []
      s = prand.randrange(1, group.n, "kqjelqkwjrq")
      yield pt, r, s, "extreme value for k", []


