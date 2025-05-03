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

import xdh
import xdh_ktv
import asn_parser
import base64
import pprint


# Basically just a way to add more information of RFC 7748 to this code.
def test_isomorphisms():
  # generator of edwards25519
  x25519 = xdh.x25519
  px = int("1511222134953540077250115140958853151145401269304185720604611328"
           "3949847762202")
  py = int("4631683569492647816942839400347516314130799386625622561578303360"
           "3165251855960")
  x, y = xdh.x25519isomorphism.convert_uv2xy(x25519.pu, x25519.pv)
  assert px == x
  assert py == y
  u, v = xdh.x25519isomorphism.convert_xy2uv(px, py)
  assert u == x25519.pu
  assert v == x25519.pv

  # generator for the edwards curve in Section 4.2 of RFC 7748
  x448 = xdh.x448
  px = int("345397493039729516374008604150537410266655260075183290216406970"
           "281645695073672344430481787759340633221708391583424041788924124"
           "567700732")
  py = int("363419362147803445274661903944002267176820680343659030140745099"
           "590306164083365386343198191849338272965044442230921818680526749"
           "009182718")
  x, y = xdh.x448isomorphism.convert_uv2xy(x448.pu, x448.pv)
  assert px == x
  assert py == y
  u, v = xdh.x448isomorphism.convert_xy2uv(px, py)
  assert u == x448.pu
  assert v == x448.pv


def test_x448_mapping():
  # Generator of edwards448
  x448 = xdh.x448
  px = int("224580040295924300187604334099896036246789641632564134246125461"
           "686950415467406032909029192869357953282578032075146446173674602"
           "635247710")
  py = int("298819210078481492676017930443930673437544040154080242095928241"
           "372331506189835876003536878655418784733982303233503462500531545"
           "062832660")
  x, y = xdh.x448isomorphism.convert_uv2xy(x448.pu, x448.pv)
  assert px == x
  assert py == y
  u, v = xdh.x448isomorphism.convert_xy2uv(x, y)
  assert u == x448.pu
  assert v == x448.pv


def point_mult_isomorphism(iso, u, v, k):
  """Performs a point multiplication using the edwards curve."""
  x, y = iso.convert_uv2xy(u, v)
  P = iso.B.point(x, y)
  R = P * k
  return iso.convert_xy2uv(R.x, R.y)


def test_point_mult_isomorphism():
  for iso in [xdh.x25519isomorphism, xdh.x448isomorphism]:
    k = 123456789
    u, v = point_mult_isomorphism(iso, iso.A.pu, iso.A.pv, k)
    u2 = iso.A.point_mult(iso.A.pu, k)
    assert u == u2


def test_vectors(alg, vectors):
  for priv_a_hex, pub_a_hex, priv_b_hex, pub_b_hex, secret_hex in vectors:
    priv_a = bytes.fromhex(priv_a_hex)
    priv_b = bytes.fromhex(priv_b_hex)
    pub_a = bytes.fromhex(pub_a_hex)
    pub_b = bytes.fromhex(pub_b_hex)
    secret1 = alg.shared_secret(priv_a, pub_b)
    assert secret1.hex() == secret_hex
    secret2 = alg.shared_secret(priv_b, pub_a)
    assert secret2.hex() == secret_hex


PRIV_KEY_SAMPLES = [
    # SEQUENCE {
    #    INTEGER 0x01 (1 decimal)
    #    SEQUENCE {
    #       OBJECTIDENTIFIER 1.3.101.110
    #    }
    #    OCTETSTRING
    #        0420b0133d068310a879ff6334b00ca7293f3757465110eb24b42dbb1cb00ad25b65
    #    [1] 00d8151c45bb0adce0e1321f3169d7adf952e0a2be184f8e9b2bf73e8d0fead904
    # }
    # - BC includes the public key. Because of this the version is 1.
    # - The private key is encoded as Octetstring of Octetstring. This is
    #   consistent with RFC 8410.
    # - There is no NULL parameter after the OID. This is consistent with RFC
    #   8410.
    {
        "src": "BouncyCastle",
        "format": "pkcs8",
        "alg": "x25519",
        "encoding":
            "3051020101300506032b656e04220420b0133d068310a879ff6334b00ca7293f"
            "3757465110eb24b42dbb1cb00ad25b65812100d8151c45bb0adce0e1321f3169"
            "d7adf952e0a2be184f8e9b2bf73e8d0fead904"
    },
    {
        "src":
            "RFC 8410",
        "format":
            "base64",
        "alg":
            "ed25519",
        "encoding":
            b"MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC"
    },
    {
        "src": "RFC 8410",
        "format": "base64",
        "alg": "ed25519",
        "encoding":
            b"MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC"
            b"oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB"
            b"Z9w7lshQhqowtrbLDFw4rXAxZuE="
    },
    {
        "src": "Cavium HSM?",
        "format": "base64",
        "alg": "x25519",
        "encoding":
            b"MC4CAQAwBQYDK2VuBCIEIHhsrAyIghuTBx4QDX94Su81o5E8P3eyqBFydKL7wKpU"
    },
    {
        "src": "Cavium HSM?",
        "format": "base64",
        "alg": "x448",
        "encoding":
            b"MEYCAQAwBQYDK2VvBDoEOATt+e2DH8x4OlCSEqwqkcV4k43oQD+Yi/8Eowltlwhn"
            b"zqRygQi7oaBF0MtYVnDD6nUdycJlRljJ"
    },    
]

PUB_KEY_SAMPLES = [
    # SEQUENCE {
    #    SEQUENCE {
    #       OBJECTIDENTIFIER 1.3.101.110
    #    }
    #    BITSTRING
    #        0xd8151c45bb0adce0e1321f3169d7adf952e0a2be184f8e9b2bf73e8d0fead904
    #        : 0 unused bit(s)
    # }
    #
    # - There is no Null after the OID. This is consistent with RFC 8410.
    {
        "src": "BouncyCastle",
        "format": "x509",
        "alg": "x25519",
        "encoding":
            "302a300506032b656e032100d8151c45bb0adce0e1321f3169d7adf952e0a2be"
            "184f8e9b2bf73e8d0fead904"
    }
]


def print_struct(s):
  pp = pprint.PrettyPrinter(width=80, indent=2)
  pp.pprint(s)


def print_asn(b: bytes):
  struct = asn_parser.parse(b)
  print_struct(struct)


def test_samples():

  def get_encoding(t):
    if t["format"] == "base64":
      return base64.b64decode(t["encoding"])
    else:
      return bytes.fromhex(t["encoding"])

  for t in PRIV_KEY_SAMPLES:
    print(f'{t["src"]}: {t["alg"]}')
    print_asn(get_encoding(t))
  for t in PUB_KEY_SAMPLES:
    print(f'{t["src"]}: {t["alg"]}')
    print_asn(get_encoding(t))


def test_encode():
  priv = bytes.fromhex(
      "b0133d068310a879ff6334b00ca7293f3757465110eb24b42dbb1cb00ad25b65")
  pub = bytes.fromhex(
      "d8151c45bb0adce0e1321f3169d7adf952e0a2be184f8e9b2bf73e8d0fead904")
  expected = bytes.fromhex(
      "3051020101300506032b656e04220420b0133d068310a879ff6334b00ca7293f"
      "3757465110eb24b42dbb1cb00ad25b65812100d8151c45bb0adce0e1321f3169"
      "d7adf952e0a2be184f8e9b2bf73e8d0fead904")
  encoded = xdh.x25519.asn_encode_priv(priv, pub)
  if expected != encoded:
    print_asn(expected)
    print_asn(encoded)
    assert False


if __name__ == "__main__":
  test_isomorphisms()
  test_point_mult_isomorphism()
  test_vectors(xdh.x25519, xdh_ktv.TESTVECTORS_X25519)
  test_vectors(xdh.x448, xdh_ktv.TESTVECTORS_X448)
  test_samples()
  test_encode()
