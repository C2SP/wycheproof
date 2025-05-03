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

import base64
import modify
import util

# This module mostly follows the definition in RFC 7468.
#
# References:
# -----------
#
# RFC 7468 has a useful definition for a PEM encodings. This RFC defines
# a strict encodings. The main idea is that all PEM encoders should generate
# PEMs with according to the rules of the strict encoding.
# RFC 7468 also defines a lax encoding. Here the idea is that PEM decoders
# are encouraged to also accept lax encodings.
#
# RFC 1421 is another definition for PEM encodings. The two definitions are
# not entirely compatible with each other. In particular, RFC 1421 allows
# headers, e.g. lines like:
#   Proc-Type: 4, ENCRYPTED
#   Content-Domain: RFC822
#
# Headers are excluded in RFC 7468. Nevertheless, it is expected that crypto
# libraries contain just one parser covering use cases of RFC 7468 and RFC 1421.
# Hence it is at the moment a bit unclear to me how to treat libraries that
# accept headers in PEM encodings that do not specify headers.
#
# One such library is BouncyCastle, even seems to allow mixing headers and
# content.


class PemFormat:
  def __init__(self, label: str, structure = None, alt_structure = None):
    self.label = label
    self.structure = structure
    self.alt_structure = alt_structure

  def wrap_asn(self, asn: bytes) -> str:
    asnb64 = base64.b64encode(asn).decode("ascii")
    lines = [self.header()]
    lines += [asnb64[i:i + 64] for i in range(0, len(asnb64), 64)]
    lines.append(self.footer())
    # RFC 7468 defines a strict encoding for PEM. The definition for the
    # strict encoding allows different ways to indicate an end of line and
    # leaves it open if there is an eol at the end of the encoding. Having
    # an eol at the end of the encoding seems popular.
    lines.append("")
    return "\n".join(lines)

  def generate_lax_pem(self, asn: bytes):
    """Yields lax pem encodings.

    RFC 7468 defines a strict encoding for PEM and a lax encoding.
    It recommends that implementations generate PEM according to the strict
    encoding rules. However, when parsing keys lax encodings can be accepted.

    Args:
      asn: the ASN encoded content of the PEM

    Yields:
      Tuples (pem, validity, comment), where encoding is the
      encoding of the key, validity is one of ("valid", "acceptable", "invalid")
      comment is a description of the modification.
    """
    for res in modify.CaseIter(modified_pem, asn, self):
      (pem, validity), comment = res
      yield pem, validity, comment

  def header(self):
    if self.label is None:
      raise ValueError("label is undefined. Use a subclass.")
    return f"-----BEGIN {self.label}-----"

  def footer(self):
    if self.label is None:
      raise ValueError("label is undefined. Use a subclass.")
    return f"-----END {self.label}-----"


# TODO: Add unclear cases:
#     - garbage before header
#     - garbage after header
#     - additional new lines
#     - invalid characters in base64
#     - spaces in base64
#     - missing '=='
#     - incorrect length in base64
#     - multiple keys
#     - wrong footer
#     - misformed header or footer
#     - literature search, CVE search
@util.type_check
def modified_pem(case,
                 encoding: bytes, 
                 pem_format: PemFormat) -> tuple[str, str]:
  validity = "valid"
  header = pem_format.header()
  footer = pem_format.footer()
  b64 = base64.b64encode(encoding)
  asnb64 = b64.decode("ascii")
  lines = [header]
  line_length = 64
  if case("adding unused header"):
    lines.append("Content-Domain: RFC822")
    validity = "acceptable"
  if case("using lines of length 80 instead of 64"):
    line_length = 80
    # lax encoding
    validity = "acceptable"
  lines += [
      asnb64[i:i + line_length] for i in range(0, len(asnb64), line_length)
  ]
  lines.append(footer)
  eol = "\n"  # LF
  if case("additional newline after footer"):
    lines.append("")
  for other_eol, desc, val in (
    ("\r", "CR", "valid"),
    ("\r\n", "CRLF", "valid"),
    (" \n", "space before newline", "acceptable")):
    if case("using " + desc + " as line delimiter"):
      eol = other_eol
      validity = val
  if case("omitting last eol"):
    pass
  else:
    lines.append("")
  return eol.join(lines), validity


def parse(pem: str):
  """Quick and dirty parser for testing.

  Allows invalid PEMs.
  """
  parts = pem.split("-----")
  if len(parts) not in (4, 5):
    raise ValueError("Unexpected format")
  header = parts[1]
  content = parts[2]
  footer = parts[3]
  if not header.startswith("BEGIN "):
    raise ValueError("Unexpected header:" + header)
  label = header[6:]
  if footer != f"END {label}":
    raise ValueError("Unexpected footer:" + footer)
  header_info = dict()
  current_key = None
  checksum = None
  b64 = ""
  for line in content.split("\n"):
    if not line:
      current_key = None
    elif line[0] == "=":
      if checksum is not None:
        raise ValueError("Multiple checksums")
      checksum = line
    elif line[0] == " ":
      if current_key is None:
        raise ValueError("Unexpected space:" + line)
      else:
        header_info[current_key] += "\n" + line
    elif ":" in line:
      if b64:
        raise ValueError("mixed header info and content")
      current_key, val = line.split(":", 1)
      header_info[current_key] = val
    else:
      if current_key is not None:
        raise ValueError("header info not seperated by empty line")
      b64 += line
  return label, b64, header_info, checksum

# ----- Deprecated stuff -----
# Replace with pem_formats
PublicKeyFormat = PemFormat(label = "PUBLIC KEY")
PrivateKeyFormat = PemFormat(label = "PRIVATE KEY")
RsaPrivateKeyFormat = PemFormat(label = "RSA PRIVATE KEY")
RsaPublicKeyFormat = PemFormat(label = "RSA PUBLIC KEY")

@util.type_check
def public_key_pem(asn: bytes) -> str:
  return PublicKeyFormat.wrap_asn(asn)


# used a lot
@util.type_check
def private_key_pem(asn: bytes) -> str:
  return PrivateKeyFormat.wrap_asn(asn)
