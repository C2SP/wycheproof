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

import gen_rsa_pss
import producer
import rsa_test_keys
import sys
import test_vector
import test
import flag

# TODO: add invalid combinations
#   https://tools.ietf.org/id/draft-ietf-lamps-pkix-shake-12.html
#   adds SHA-3 and SHAKE to RSA-PSS (and ECDSA). There are a number
#   of restrictions about the format. It might make sense to
#   test illegal parameters.
#
# hashAlgorithm:
# --------------
# Section A.2.3 defines it as a hash in OAEP-PSSDigestAlgorithms
# Appendix A.2.1 includes SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
# SHA-512/224 and SHA-512/256 as valid algorithm and allows future
# expansion.
#
# MGF1:
# -----
# RFC 8017 defines:
#   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
#           { OID id-mgf1 PARAMETERS HashAlgorithm },
#          ...  -- Allows for future expansion --
#   }
# There is no clear definition what hash functions are allowed, though
# "..., it is RECOMMENDED
#       that the underlying hash function be the same as the one
#       identified by hashAlgorithm;"
# seems to imply that one would use truncated hashes for the
# MGF if the hash algorithm is a truncated hash.


def gen_rsa_pss_misc(namespace):
  message = namespace.message.encode('ascii')
  specify_pkcs1algorithm = flag.Flag(
      label="SpecifyPkcs1Algorithm",
      bug_type=flag.BugType.FUNCTIONALITY,
      description="The test vector contains a valid RSASSA-PSS signature. "
      "Encoded public keys (i.e. publicKeyPEM and public KeyDER) contain the "
      "ASN encoding of the Pkcs1Algorithm algorithm used to sign the message. "
      "These algorithms are described in Section A.2 of RFC 8017.",
      effect="Many implementations only accept public keys with "
      "Pkcs1Algorithm = rsaEncryption. Hence an implementation that does not "
      "accept the signature in test vector likely has no support for "
      "alternative algorithm-identifiers.")
  sha1 = flag.Flag(
      label="WeakHash",
      bug_type=flag.BugType.WEAK_PARAMS,
      description="The test vector uses a weak hash (i.e. SHA-1).")
  # TODO: is there any result on using MGF1-SHA1 in RSASSA-PSS.
  mgf1_sha1 = flag.Flag(
      label="Mgf1Sha1",
      bug_type=flag.BugType.FUNCTIONALITY,
      description="The test vector uses MGF1SHA1. MGF1SHA1 is an algorithm "
      "that is still among the recommended algorithms in RFC 8017 Section B.1, "
      "while SHA-1 is of course no longer recommended for the message digest.")
  distinct_hash = flag.Flag(
      label="DistinctHash",
      bug_type=flag.BugType.FUNCTIONALITY,
      description="The test vector uses distinct hashes for computing the "
      "message digest and the MGF. This is an unusual setup. Typically "
      "RSASSA-PSS signature use the same hash functions for both. "
      "RFC 8017 recommends to use the same hash function for the message "
      "digest and the MGF. Some libraries indeed only support RSASSA-PSS "
      "with identical hashes.")
  parameter_test = flag.Flag(
      label="ParameterTest",
      bug_type=flag.BugType.FUNCTIONALITY,
      description="The test vectors in this file use unusual parameters "
      "for RSASSA-PSS. One cause for not accepting a signature is that "
      "a library only supports a restricted set of parameters.")
  specify_pss_params = getattr(namespace, "specify_pkcs1algorithm", False)
  key = rsa_test_keys.rsa_test_key2
  t = test_vector.Test("RSASSA-PSS")
  for md in ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]:
    for mgf in ["MGF1"]:
      for mgf_md in ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]:
        for slen in (0, 20, 28, 32, 48, 64):
          flags = [parameter_test]
          if specify_pss_params:
            flags += [specify_pkcs1algorithm]
          if md == "SHA-1":
            flags += [sha1]
          if mgf_md == "SHA-1":
            flags += [mgf1_sha1]
          if md != mgf_md:
            flags += [distinct_hash]
          g = gen_rsa_pss.RsassaPssTestGroup(
              rsa_test_keys.rsa_test_key2,
              md,
              mgf,
              mgf_md,
              slen,
              specify_pss_params,
              "osp",
              footnotes=t.footnotes(),
              key_flags=flags)
          g.add_signature(message)
          idx = ("rsa_%d_%s_%s_%s_%d"
                 % (key.n.bit_length(), md, mgf,mgf_md, slen))
          t.add_group(idx, g)
  return t


class RsaPssMiscProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument(
        "--message",
        type=str,
        default="",
        help="An ASCII string. Test vectors with all known hashes and mgfs"
        " will be generated for just this message.")
    res.add_argument(
        "--specify_pkcs1algorithm",
        action="store_true",
        help="Specifies that the PKCS1Algorithm (as defined in Appendix A of"
        " RFC 8017) has OID id-RSASSA-PSS and that the mgf parameters"
        " are specified. Otherwise OID rsaEncryption is is used."
        " Many crypto libraries do not accept RSA-PSS parameters"
        " in the keys.")
    return res

  def generate_test_vectors(self, namespace):
    test = gen_rsa_pss_misc(namespace)
    if getattr(namespace, "specify_pkcs1algorithm", False):
      test.header.append(
          "keyDer contains the MGF parameters specified in Appendix A of"
          " RFC 8017.")
    return test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  RsaPssMiscProducer().produce(namespace)


if __name__ == "__main__":
  RsaPssMiscProducer().produce_with_args()
