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
import collections
import pbkdf
import pbes2
import pbes2_impl
import pbes2_ktv
import flag
import producer
import prand
import test_vector
import typing
import util
from typing import Optional


class PbeTestVector(test_vector.TestVector):
  """A test vector for PBES1 and PBES2.
  
  """
  test_attributes = ["password", "salt", "iterationCount", "iv", "msg", "ct"]
  schema = {
     "password" : {
         "type" : AST.HexBytes,
         "short" : "the password (as hexadecimal encoded octet string)",
         "desc" : "The password. This is a hexadecimal encoded octet string."
         " PBKDF takes an arbitrary octet string as input. The conversion from"
         " passwords given as strings to octet string is not defined in the"
         " RFC." 
     },
     "salt" : {
         "type" : AST.HexBytes,
         "desc" : "the salt",
     },
     "iterationCount" : {
         "type" : int,
         "desc" : "the iteration count",
     },
     "iv" : {
         "type" : AST.HexBytes,
         "desc" : "the IV used for the encryption",
     },
     "msg" : {
         "type" : AST.HexBytes,
         "desc" : "the encrypted message",
     },
     "ct" : {
         "type" : AST.HexBytes,
         "desc" : "the ciphetext",
     },
  }

  def index(self):
    return ""

class PbeTest(test_vector.TestType):
  """Test vector of type PbeTest are used for PBES1 or PBES2. 
 
  """

class PbeTestGroup(test_vector.TestGroup):
  """A test group for PBES1 or PBES2."""
  algorithm = "PBE"
  testtype = PbeTest
  vectortype = PbeTestVector
  schema = {}

  def __init__(self, dummy):
    super().__init__()

  def as_struct(self, sort_by=None):
    if sort_by is None:
      sort_by = "comment"
    group = collections.OrderedDict()
    group["type"] = self.testtype
    group["tests"] = self.get_all_vectors(sort_by=sort_by)
    return group

class PbeTestGenerator(test_vector.TestGenerator):
  """A generator for PBE test vectors."""
  def __init__(self, namespace):
    self.args = namespace
    self.algorithm = namespace.alg
    self.sha = namespace.sha
    self.cipher_name = namespace.cipher
    self.key_size_in_bytes = namespace.key_size // 8
    if self.algorithm == "PBES2":
      self.pbe = pbes2_impl.Pbes2Impl(self.sha, self.cipher_name, self.key_size_in_bytes)
    self.name = self.pbe.name
    self.test = test_vector.Test(self.name)
    super().__init__()

  def new_testgroup(self, idx):
    return PbeTestGroup(idx)

  def get_pw_flags(self, pw: bytes) -> list[flag.Flag]:
    flags = []

    try:
      s = pw.decode("ascii")
      if s.isprintable():
        flags.append(flag.Flag(
          label = "Printable",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains a password consisting of printable ASCII characters."))
      else:
        flags.append(flag.Flag(
          label = "Ascii",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains a password consisting of ASCII characters."))
    except UnicodeDecodeError:
      # pw contains non-ascii characters
      try:
        s = pw.decode("utf-8")
        flags.append(flag.Flag(
            label = "Utf8",
            bug_type=flag.BugType.FUNCTIONALITY,
            description="The test vector contains a password that is a valid UTF-8 string."))
      except UnicodeDecodeError:
        flags.append(flag.Flag(
          label = "NonUtf8",
          bug_type=flag.BugType.FUNCTIONALITY,
          description="The test vector contains a password that is not a valid UTF-8 string."))
    if len(pw) % 2 == 0 and len(pw) >= 2 and pw[-2:] == bytes(2):
      try:
        pw[:-2].decode("utf-16-be")
        flags.append(flag.Flag(
            label = "BmpString",
            bug_type=flag.BugType.FUNCTIONALITY,
            description="The test vectors contains a password that is a valid BMPString as used"
            " in RFC 7292. This RFC uses big endian encoding and a null terminator."))
      except UnicodeDecodeError:
        pass
    return flags
   

  @util.type_check
  def gen_test(self,
               password: bytes,
               salt: bytes,
               iteration_count: int,
               iv: bytes,
               msg: bytes,
               ct: bytes = None,
               flags = None, 
               comment = ""):
    result = "valid"
    if flags is None:
      flags = []
    flags = flags + self.get_pw_flags(password)
    if ct is None:
      ct = self.pbe.encrypt(password, salt, iteration_count, iv, msg)
    test = PbeTestVector()
    test.comment = comment
    test.password = password
    test.salt = salt
    test.iterationCount = iteration_count
    test.iv = iv
    test.msg = msg
    test.ct = ct
    test.flags = self.add_flags(flags)
    test.result = result
    self.add_test(test)

  def generate_known_test_vectors(self):
    pass
                 
  def generate_pseudorandom(
      self,
      cnt: int,
      password_sizes: list[int],
      salt_sizes: list[int],
      iteration_counts: list[int],
      msg_lengths: list[int],
      *,
      pw_format: str = "printable",
      comment: str = "",
      seed: bytes = "",
      flags: Optional[list[str]] = None):
    """Generates pseudorandom test vectors.

    Args:
      cnt: the number of test cases generated per options
      password_sizes: as list of sizes in bytes
      salt_sizes: a list of size for the salt in bytes
      iteration_counts: a list of counts for the number of iterations
      dk_lengths: a list of lengths for the dk
      comment: describes what is special about the test cases
      seed: a seed for the pseudorandom genration
      flags: an optional ist of flags.
    """
    if not flags:
      flags = []
    for pw_size in password_sizes:
      for salt_size in salt_sizes:
        for c in iteration_counts:
          for msg_len in msg_lengths:
            for i in range(cnt):
              ident = b"%s %d %d %d %d %d" % (
                      seed, pw_size, salt_size, c, msg_len, i)
              pw = self.rand_pw(pw_format, pw_size, ident)
              salt = prand.randbytes(salt_size, b"salt:", ident)
              iv = prand.randbytes(self.pbe.iv_size, b"iv:", ident)
              msg = prand.randbytes(msg_len, b"msg:", ident)
              self.gen_test(password = pw,
                            salt=salt,
                            iteration_count = c,
                            iv=iv,
                            msg=msg,
                            comment=comment, flags=flags)

  def rand_pw(self, pw_format: str, pw_size: int, seed: bytes) -> bytes:
    pw = prand.randbytes(pw_size, b"pw", seed)
    if pw_format == "printable":
      return self.printable(pw)
    elif pw_format == "ascii":
      return bytes(x & 0x7f for x in pw)
    elif pw_format == "utf-8":
      res = bytearray()
      for i in range(0, len(pw), 2):
        c = int.from_bytes(pw[i:i+2], 'big') % 2048
        res += chr(c).encode("utf-8")
      return bytes(res)
    elif pw_format == "raw":
      return pw
    elif pw_format == "bmpstring_ascii":
      pwa = bytearray()
      for c in pw:
        pwa += bytes([0, c & 0x7f])
      return bytes(pwa) + bytes(2)
    elif pw_format == "bmpstring":
      if len(pw) % 2 == 1:
        pw = pw[:-1]
      pw = bytearray(pw)
      for i in range(0, len(pw), 2):
        # we don't want to generate code points > 0xffff
        if pw[i] >= 0xd8 and pw[i] < 0xe0:
          pw[i] = 0x00
      # convert to bytes and add NULL terminator:
      return bytes(pw) + bytes(2)
    else:
     raise ValueError("Unknown format:" + pw_format)

  def printable(self, b: bytes) -> bytes:
    chars = bytes(i for i in range(128) if chr(i).isprintable())
    return bytes(chars[x % len(chars)] for x in b)

  def generate_special_case(self, salt_sizes, iter_counts, msg_lengths, seed=b"k23hklado23u4"):
    for p, comment in [([0xff],""),
              ([0xc0], "special case: truncated UTF-8 string"),
              ([0xff]*8,"special case: invalid UTF-8 bytes"),
              ([0xc0]*8,"special case: invalid 2 byte UTF-8 code points"),
              ([0xee]*8,"special case: invalid 3 byte UTF-8 code points"),
              ([0xf0]*8,"special case: invalid UTF-8 code points"),
              ([0xdb]*8,"special case for UTF-16"),
              ([0]*65,"special case: long all zero password"),
              ]:
      # Potential bugs: CVE-2008-2938 and CVE-2012-2135
      pw = bytes(p)
      if not comment:
        comment="special case password"
      for salt_size in salt_sizes:
        for c in iter_counts:
          for msg_len in msg_lengths:
            ident = b"%s %s %d %d %d" % (pw, seed, salt_size, c, msg_len)
            salt = prand.randbytes(salt_size, b"salt:", ident)
            iv = prand.randbytes(self.pbe.iv_size, b"iv:", ident)
            msg = prand.randbytes(msg_len, b"msg:", ident)
            self.gen_test(password = pw,
                          salt=salt,
                          iteration_count = c,
                          iv=iv,
                          msg=msg,
                          comment=comment)
          
  def generate_all(self):
    # TODO:
    #   - add test vectors with invalid padding
    #   - add test vectors with empty keys
    self.generate_known_test_vectors()
    # typical
    salt_sizes = [8, 16]
    msg_lengths = [16, 17]
    # message sizes
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[8],
                               salt_sizes=salt_sizes[:1],
                               iteration_counts=[4096],
                               pw_format = "printable",
                               comment = "printable password",
                               msg_lengths=list(range(33)),
                               seed=b"j9182741d") 
    # ascii
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[12, 20],
                               salt_sizes=salt_sizes,
                               iteration_counts=[4096],
                               comment = "password contains only ASCII characters",
                               pw_format = "ascii",
                               msg_lengths=msg_lengths,
                              seed=b"j91123d")
    #utf-8
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[8, 17],
                               salt_sizes=salt_sizes,
                               iteration_counts=[4096],
                               msg_lengths=msg_lengths,
                               pw_format="utf-8",
                               comment="password is a valid UTF-8 encoding",
                               seed=b"jklkj2dsfaaid")
    #non-utf8
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[8, 17],
                               salt_sizes=salt_sizes,
                               iteration_counts=[4096],
                               msg_lengths=msg_lengths,
                               pw_format="raw",
                               comment="password is a random byte string",
                               seed=b"jklkj2dsfaaid")
    #BMPString
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[1, 8, 16],
                               salt_sizes=salt_sizes[:1],
                               iteration_counts=[4096],
                               msg_lengths=msg_lengths,
                               pw_format="bmpstring_ascii",
                               comment="password is an ASCII string encoded as BMPString",
                               seed=b"j2138,sr2134d")
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[2, 8, 16],
                               salt_sizes=salt_sizes[:1],
                               iteration_counts=[4096],
                               msg_lengths=msg_lengths,
                               pw_format="bmpstring",
                               comment="password is a BMPString",
                               seed=b"j2138,sr2134d")
    #empty password
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[0],
                               salt_sizes=salt_sizes[:1],
                               msg_lengths=msg_lengths,
                               iteration_counts=[4096],
                               comment="empty password",
                               seed=b"2;kj3hsoiyu4")
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[0],
                               salt_sizes=salt_sizes[:1],
                               msg_lengths=msg_lengths,
                               iteration_counts=[4096],
                               pw_format="bmpstring",
                               comment="password is an empty BMPString",
                               seed=b"2;l23k4jsse33")
    self.generate_pseudorandom(cnt=1,
                               password_sizes=[65, 129, 257],
                               salt_sizes=salt_sizes[:1],
                               iteration_counts=[4096],
                               msg_lengths=msg_lengths[:1],
                               pw_format="printable",
                               comment="long password",
                               seed=b"jk197823123d")
    self.generate_special_case(salt_sizes=salt_sizes[:1],
                               iter_counts=[4096],
                               msg_lengths=msg_lengths[:1])


class PbeProducer(producer.Producer):

  def parser(self):
    res = self.default_parser()
    res.add_argument("--alg",
                     type=str,
                     default="PBES2",
                     choices=["PBES2"])
    res.add_argument("--sha",
                     type=str,
                     default="SHA-1",
                     choices=pbkdf.SUPPORTED_HASHES)
    res.add_argument("--cipher",
                     type=str,
                     default="AES-CBC",
                     choices=["AES-CBC"])
    res.add_argument("--key_size",
                     type=int,
                     default=128)
    return res

  def generate_test_vectors(self, namespace):
    tv = PbeTestGenerator(namespace)
    tv.generate_all()
    return tv.test


# DEPRECATED: Use Producer.produce() instead
def main(namespace):
  PbeProducer().produce(namespace)


if __name__ == "__main__":
  PbeProducer().produce_with_args()
