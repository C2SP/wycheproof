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

import AST
import eddsa
import eddsa_ktv
import flag
import producer
import sig_test_vector
import test_vector
import util
import prand
from typing import Optional

ALGORITHMS = ["ed25519", "ed448"]

# TODO: More refactoring:
#   - Split EddsaTestGroup into EddsaTestGroup and a test generation class.
#
# Does eprint.iacr.org/2020/1244.pdf have some interesting ideas?
#   Analyzes binding signature schems (comparable to non-repudiation: can"t
#   generate a signature for two distinct messages), strongly binding:
#   can"t generate a signature for two public keys.)
#   This property requires checking public keys for low order points.
#
# Check this:
#   - signatures with s slightly larger than n
#   - signatures with s slightly smaller than n
#   - same for r
# One thing that can be done is generating invalid signatures with low
#   order points as public key.
#
EddsaTestVector = sig_test_vector.SignatureTestVector

class EddsaVerify(test_vector.TestType):
  """Test vectors of type EddsaVerify are intended for testing

     the verification of Eddsa signatures.
  """


class EddsaSign(test_vector.TestType):
  """Test vectors of type EddsaVerify are intended for testing

     the generation of Eddsa signatures.
  """


class EddsaVerifyTestGroup(test_vector.TestGroup):
  algorithm = "EDDSA"
  testtype = EddsaVerify
  vectortype = EddsaTestVector
  schema = {
      "publicKey": {
          "type": "Json",
          "desc": "unencoded public key",
      },
      "publicKeyDer": {
          "type": AST.Der,
          "desc": "Asn encoded public key",
      },
      "publicKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded public key",
      },
      "publicKeyJwk": {
          "type": "Json",
          "desc": "the public key in webcrypto format",
          "since": "0.7",
          "ref": "RFC 8037 Section 2",
      },
  }

  def __init__(self, pk):
    super().__init__()
    self.pk = pk

  def key_as_struct(self):
    group = self.pk.group
    d = {
        "type": "EDDSAPublicKey",
        "curve": group.curve.name,
        "keySize": group.mod.bit_length(),
        "pk": self.pk.raw(),
    }
    return d

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["publicKey"] = self.key_as_struct()
    group["publicKeyDer"] = self.pk.encode()
    group["publicKeyPem"] = self.pk.pem()
    group["publicKeyJwk"] = self.pk.jwk()
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EddsaSignTestGroup(test_vector.TestGroup):
  algorithm = "EDDSA"
  testtype = EddsaSign
  vectortype = EddsaTestVector
  schema = {
      "keyPair": {
          "type": "Json",
          "desc": "unencoded key pair",
      },
      "privateKeyDer": {
          "type": AST.Der,
          "desc": "Asn encoded private key",
      },
      "privateKeyPem": {
          "type": AST.Pem,
          "desc": "Pem encoded private key",
      },
      "privateKeyJwk": {
          "type": "Json",
          "desc": "the private key in webcrypto format",
          "since": "0.7",
          "ref": "RFC 8037 Section 2",
      },
  }

  def __init__(self, sk):
    super().__init__()
    self.sk = sk
    self.pk = sk.publickey()

  def keypair_as_struct(self):
    group = self.sk.group
    d = {
        "type": "EDDSAKeyPair",
        "curve": group.curve.name,
        "keySize": group.mod.bit_length(),
        "pk": self.pk.raw(),
        "sk": self.sk.raw(),
    }
    return d

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = {}
    group["type"] = self.testtype
    group["keyPair"] = self.keypair_as_struct()
    # TODO: Isn't there a private key encoding
    # group["privateKeyDer"] = self.pk.encode()
    # group["privateKeyPem"] = self.pk.pem()
    group["privatKeyJwk"] = self.sk.jwk()
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group


class EddsaTestGenerator(test_vector.TestGenerator):
  algorithm = "EDDSA"

  def __init__(self, test_signing: bool = False):
    super().__init__()
    self.test_signing = test_signing
    self.test = test_vector.Test(self.algorithm)

  @util.type_check
  def get_group_priv(
      self, privkey: Optional[eddsa.EddsaPrivateKey]) -> test_vector.TestGroup:
    """Returns the TestGroup for a private key.

    Eddsa test vectors are group into TestGroup, where each test group
    contains the test vectors with the same private key. This function
    checks if the key is already known and either returns an existing
    group or creates a new one.

    Args:
      privkey: the private key

    Returns:
      the corresponding TestGroup.
    """
    pubkey = privkey.publickey()
    keyid = pubkey.raw().hex()
    if keyid in self.test.testgroups:
      return self.test.testgroups[keyid]
    if self.test_signing:
      new_group = EddsaSignTestGroup(privkey)
    else:
      new_group = EddsaVerifyTestGroup(pubkey)
    self.test.add_group(self, new_group)
    return new_group

  @util.type_check
  def get_group_pub(
      self, pubkey: Optional[eddsa.EddsaPublicKey]) -> test_vector.TestGroup:
    """Returns the TestGroup for a public key.

    Eddsa test vectors are group into TestGroup, where each test group
    contains the test vectors with the same private key. This function
    checks if the key is already known and either returns an existing
    group or creates a new one.

    Args:
      pubkey: the public key

    Returns:
      the corresponding TestGroup.
    """
    keyid = pubkey.raw().hex()
    if keyid in self.test.testgroups:
      return self.test.testgroups[keyid]
    if self.test_signing:
      raise ValueError("Needs private key")
    else:
      new_group = EddsaVerifyTestGroup(pubkey)
    self.test.add_group(self, new_group)
    return new_group

  @util.type_check
  def add_test_sig(self,
                   test_group: test_vector.TestGroup,
                   result: str,
                   comment: str,
                   message: bytes,
                   sig: bytes,
                   *,
                   flags: Optional[list[flag.Flag]] = None):
    """Adds a test vector."""
    labels = self.add_flags(flags)
    tc = EddsaTestVector(
        msg=message, sig=sig, comment=comment, result=result, flags=labels)
    test_group.add_test(tc)

  def generate_valid(self, sk: eddsa.EddsaPrivateKey) -> None:
    """Generates a number of valid signatures.

    Args:
      sk: the private key for which the signatures are generated.
    """
    valid = flag.Flag(
        label="Valid",
        bug_type=flag.BugType.BASIC,
        description="The test vector is an ordinary valid signature.")

    messages = [
        b"", b"x", b"Test", b"Hello", b"123400",
        bytes(12), b"a" * 65,
        bytes(range(32, 97)),
        bytes([255]) * 16
    ]
    test_group = self.get_group_priv(sk)
    for m in messages:
      self.add_test_sig(test_group, "valid", "", m, sk.sign(m), flags=[valid])

  def invalid_encoding(self, sk: eddsa.EddsaPrivateKey, R: eddsa.EddsaPoint):
    """Generates invalid encodings of a point R.

    Eddsa is expected to be non-malleable. Hence
    any modification of the encoding of R in the signature
    should be detected, even if the bits are typically
    cleared during decoding.

    Args:
      sk: the private key
      R: the point to encode and modify
    """
    group = sk.group
    E = group.encodepoint(R)
    elem_size = len(E)
    bits = [0, 1, 2, 7, 8, 16, 31, 32, 63, 64, 97, 127, 240, 247, 248, 253,
            254, 255]
    if elem_size >= 57:
      bits += [440, 441, 447, 448, 449, 454, 455]
    for b in bits:
      B = bytearray(E)
      byte, bit = divmod(b, 8)
      B[byte] ^= 1 << bit
      yield "modified bit %s in R" % b ,bytes(B)
    yield "R==0", bytes(len(E))
    yield "invalid R", bytes([255]*len(E))
    # Eddsa should be non-malleable. Hence encoding -R should be
    # detected by the verification.
    yield "encoded -R", group.encodepoint(-R)
    yield "all bits flipped in R", bytes(x ^ 255 for x in E)

  def generate_invalid(self,
                       sk: eddsa.EddsaPrivateKey,
                       message: bytes = b"123400") -> None:
    """Generates signatures with invalid encodings.

    Args:
      sk: the secret key
      message: the message to sign.
    """
    invalid_encoding = flag.Flag(
        label="InvalidEncoding",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains a signature with an "
        "invalid encoding of the values. The vector checks that "
        "invalid encodings are not accepted.",
        effect="The effect of accepting such signatures is unclear. "
        "It could lead to signature malleability, be benign, or hide "
        "something more severe.")
    pubkey = sk.publickey()
    group = sk.group
    test_group = self.get_group_priv(sk)
    # Doesn't have to be deterministic
    # TODO: extend to other groups
    elem_size = group.elem_size
    r = group.Hint(sk.h[elem_size:2 * elem_size] + message)
    R = r * group.B
    for comment, Rmod in self.invalid_encoding(sk, R):
      # Compute S using a modified encoding of R.
      # I.e. if an implementation verifies the signature by computing
      # the point R from S, and the hash of R, pk and the message then
      # the implementation will get the unmodified point.
      hm = group.Hint(Rmod + pubkey.raw() + message)
      S = (r + hm * sk.a) % group.order
      sig = Rmod + group.encodeelem(S)
      self.add_test_sig(
          test_group,
          "invalid",
          comment,
          message,
          sig,
          flags=[invalid_encoding])

  def generate_rs(self, sk: eddsa.EddsaPrivateKey) -> None:
    """Generates signatures with invalid r and s.

    Args:
      sk: the secret key
    """
    edge_case_values = flag.Flag(
        label="InvalidSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The test vector contains a signature with edge case "
        "values such as 0 or the order of the group.",
        effect="The effect of accepting such signatures probably "
        "indicates that signatures can be forged without even knowing "
        "the message itself.")
    test_group = self.get_group_priv(sk)
    group = sk.group
    for r in (0, 1, group.order, group.mod):
      for s in (0, 1, group.order - 1, group.order, group.mod):
        sig = group.encodeelem(r) + group.encodeelem(s)
        self.add_test_sig(
            test_group,
            "invalid",
            "special values for r and s",
            b"?",
            sig,
            flags=[edge_case_values])

  def generate_wrong_length(self,
                            sk: eddsa.EddsaPrivateKey,
                            message: bytes = b"Test") -> None:
    """Generates signatures with the wrong length.

    Eddsa signatures should be non-malleable. The test vectors generated
    in this function contain signatures with the wrong length.
    This tests if signature verification, ignores some bytes in the signature
    and hence allows malleable signatures.

    Args:
      sk: the private key
      message: the message to sign
    """
    additional_bytes = flag.Flag(
        label="SignatureWithGarbage",
        bug_type=flag.BugType.SIGNATURE_MALLEABILITY,
        description="The test vector contains a signature with additional "
        "content. EdDSA signature are expected to be non-malleable. "
        "Signatures of the wrong length should be rejected. "
        "See RFC 8032, Section 5.2.7 and Section 8.4.")
    truncated = flag.Flag(
        label="TruncatedSignature",
        bug_type=flag.BugType.AUTH_BYPASS,
        description="The test vector contains a signature that was "
        "truncated.",
        effect="Accepting such signatures likely means that "
        "signatures can be forged.")
    compressed = flag.Flag(
        label="CompressedSignature",
        bug_type=flag.BugType.CAN_OF_WORMS,
        description="The test vector contains a signature where r and s "
        "overlap or where 0 bytes were cut from the signature. "
        "This signature was specifically generated.",
        effect="The effect of the bug is unclear without further analysis. "
        "It could be rather benign and just allow signature malleability "
        "in some cases or it could hide a more severe flaw.")

    elem_size = sk.group.elem_size
    sig = sk.sign(message)
    pubkey = sk.publickey()
    test_group = self.get_group_priv(sk)
    self.add_test_sig(
        test_group,
        "invalid",
        "empty signature",
        message,
        b"",
        flags=[truncated])
    self.add_test_sig(
        test_group,
        "invalid",
        "s missing",
        message,
        sig[:len(sig) // 2],
        flags=[truncated])
    self.add_test_sig(
        test_group,
        "invalid",
        "signature too short",
        message,
        sig[:-2],
        flags=[truncated])
    self.add_test_sig(
        test_group,
        "invalid",
        "signature too long",
        message,
        sig + b"  ",
        flags=[additional_bytes])
    sigPk = sk.sign(pubkey.raw() + message)
    self.add_test_sig(
        test_group,
        "invalid",
        "include pk in signature",
        message,
        sig + pubkey.raw(),
        flags=[additional_bytes])
    self.add_test_sig(
        test_group,
        "invalid",
        "prepending 0 byte to signature",
        message,
        bytes([0]) + sig,
        flags=[additional_bytes])
    self.add_test_sig(
        test_group,
        "invalid",
        "prepending 0 byte to s",
        message,
        sig[:elem_size] + bytes([0]) + sig[elem_size:],
        flags=[additional_bytes])
    self.add_test_sig(
        test_group,
        "invalid",
        "appending 0 byte to signature",
        message,
        sig + bytes([0]),
        flags=[additional_bytes])

    done = [False] * 4
    for i in range(2000):
      if False not in done:
        break
      msg = message + (b"%d" % i)
      sig = sk.sign(msg)
      r,s = sig[:elem_size], sig[elem_size:]
      if not done[0] and s[0] == 0:
        self.add_test_sig(
            test_group,
            "invalid",
            "removing 0 byte from signature",
            msg,
            r + s[1:],
            flags=[compressed])
        done[0] = True
      if not done[1] and s[-1] == 0:
        self.add_test_sig(
            test_group,
            "invalid",
            "removing 0 byte from signature",
            msg,
            r + s[:-1],
            flags=[compressed])
        done[1] = True
      if not done[2] and r[-1] == s[0] and s[0] != 0:
        self.add_test_sig(
            test_group,
            "invalid",
            "dropping byte from signature",
            msg,
            r + s[1:],
            flags=[compressed])
        done[2] = True
      if not done[3] and r[0] == 0:
        self.add_test_sig(
            test_group,
            "invalid",
            "removing leading 0 byte from signature",
            msg,
            r[1:] + s,
            flags=[compressed])
        done[3] = True

  def generate_malleable(self,
                         sk: eddsa.EddsaPrivateKey,
                         message: bytes = b"Test") -> None:
    sig_malleability = flag.Flag(
        label="SignatureMalleability",
        bug_type=flag.BugType.SIGNATURE_MALLEABILITY,
        description="EdDSA signatures are non-malleable, if implemented "
        "correctly. If an implementation fails to check the range of S "
        "then it may be possible to modify a signature in such a way "
        "that it still verifies. "
        "See RFC 8032, Section 5.2.7 and Section 8.4.")
    sig = sk.sign(message)
    group = sk.group
    test_group = self.get_group_priv(sk)
    elem_size = group.elem_size
    R = sig[:elem_size]
    s = eddsa.decodeint(sig[elem_size:])
    n = group.order
    p = group.mod
    # TODO: extend
    bits = group.mod.bit_length()
    for w in (n, 2 * n, 4 * n, 8 * n, 2 ** (bits - 2), 2 ** (bits - 1), 2 ** bits, p):
      s2 = s + w
      msig = R + group.encodeelem(s2)
      self.add_test_sig(
          test_group,
          "invalid",
          "checking malleability ",
          message,
          msig,
          flags=[sig_malleability])

  def generate_all(self, sk: eddsa.EddsaPrivateKey) -> None:
    """Generates all (general) test signatures.

    Args:
      sk: the secret key to use
    """
    self.generate_valid(sk)
    if not self.test_signing:
      self.generate_rs(sk)
      self.generate_wrong_length(sk)
      self.generate_invalid(sk)
      self.generate_malleable(sk)

  def generate_test_vectors(self, alg: str):
    if alg == "ed25519":
      group = eddsa.ed25519_group
    elif alg == "ed448":
      group = eddsa.ed448_group
    else:
      raise ValueError("Group not implemented for:" + alg)

    if alg == "ed25519":
      sk1 = "add4bb8103785baf9ac534258e8aaf65f5f1adb5ef5f3df19bb80ab989c4d64b"
      priv = eddsa.EddsaPrivateKey(bytes.fromhex(sk1), group)
    elif alg == "ed448":
      sk2 = prand.randbytes(group.elem_size, seed=b"j81tk2j31")
      priv = eddsa.EddsaPrivateKey(sk2, group)

    self.generate_all(priv)

    # Generate test vectors with some special case keys.
    # TODO: - large/small values for a
    ktv = flag.Flag(
        label="Ktv",
        bug_type=flag.BugType.BASIC,
        description="The test vector contains a known valid signature.")
    invalid_ktv = flag.Flag(
        label="InvalidKtv",
        bug_type=flag.BugType.UNKNOWN,
        description="The test vector contains a known invalid signature.")
    key_list = []
    if alg == "ed25519":
      key_list = [
          # 00 in key
          "0a23a20072891237aa0864b5765139514908787878cd77135a0059881d313f00",
      ]
    for k in key_list:
      priv = eddsa.EddsaPrivateKey(bytes.fromhex(k), group)
      self.generate_valid(priv)

    for t in eddsa_ktv.Tests:
      if t.alg == alg:
        sk = eddsa.EddsaPrivateKey(bytes.fromhex(t.sk_hex), group)
        test_group = self.get_group_priv(sk)
        msg = bytes.fromhex(t.msg_hex)
        sig2 = sk.sign(msg)
        comment = t.tc
        if t.sig_hex is None:
          self.add_test_sig(
              test_group, "valid", comment, msg, sig2, flags=[ktv])
        else:
          sig = bytes.fromhex(t.sig_hex)
          if sig == sig2:
            self.add_test_sig(
                test_group, "valid", comment, msg, sig, flags=[ktv])
          else:
            self.add_test_sig(
                test_group, "invalid", comment, msg, sig, flags=[invalid_ktv])

    # Tink overflow.
    tink_overflow = flag.Flag(
        label="TinkOverflow",
        bug_type=flag.BugType.KNOWN_BUG,
        description="The test vector contains a signature that caused an "
        "arithmetic overflow in tink.")
    if alg == "ed25519":
      for key_hex, msg_hex in eddsa_ktv.TINK_FAILURES:
        sk = eddsa.EddsaPrivateKey(bytes.fromhex(key_hex), group)
        test_group = self.get_group_priv(sk)
        msg = bytes.fromhex(msg_hex)
        comment = "regression test for arithmetic error"
        sig = sk.sign(msg)
        self.add_test_sig(
            test_group, "valid", comment, msg, sig, flags=[tink_overflow])
    return self.test


class EddsaProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--op",
        type=str,
        choices=["sig", "ver"],
        default="ver",
        help=("Determines whether the signatures are used for testing the"
              " signature generation or the verification."))
    res.add_argument(
        "--algorithm",
        type=str,
        choices=ALGORITHMS,
        default="ed25519",
        help="The algorithm that is tested.")
    return res

  # TODO: Most of the stuff in here belongs into the generator.
  def generate_test_vectors(self, namespace):
    op = getattr(namespace, "op", "ver")
    alg = namespace.algorithm
    gen = EddsaTestGenerator(op == "sig")
    return gen.generate_test_vectors(alg)


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  EddsaProducer().produce(namespace)


if __name__ == "__main__":
  EddsaProducer().produce_with_args()
