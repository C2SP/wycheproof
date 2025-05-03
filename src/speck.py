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

def rotate_right(x: int, r: int, bits: int) -> int:
  mask = (1 << bits) - 1
  return ((x >> r) | (x << (bits - r))) & mask


def rotate_left(x: int, r: int, bits: int) -> int:
  mask = (1 << bits) - 1
  return ((x >> (bits - r)) | (x << r)) & mask


def r(x: int, y: int, k: int, bits: int):
  mask = (1 << bits) - 1
  x = rotate_right(x, 8, bits)
  x = (x + y) & mask
  x ^= k
  y = rotate_left(y, 3, bits)
  y ^= x
  return x, y


def rinv(x: int, y: int, k: int, bits: int):
  mask = (1 << bits) - 1
  y ^= x
  y = rotate_right(y, 3, bits)
  x ^= k
  x = (x - y) & mask
  x = rotate_left(x, 8, bits)
  return x, y


class Speck:

  def __init__(self, key: bytes):
    if not hasattr(self, "block_size_in_bytes"):
      raise ValueError("block size undefined. Use a subclass")
    if len(key) not in self.key_sizes_in_bytes:
      raise ValueError("Incorrect key size")
    self.m = 2 * len(key) // self.block_size_in_bytes
    self.word_size = 4 * self.block_size_in_bytes
    self.round_keys = self.expand_key(key, self.rounds[self.m])

  def unpack(self, b: bytes):
    """Unpacks a block into integers.

    Args:
      b: a block

    Returns:
      a list of integers
    """
    wsize = self.block_size_in_bytes // 2
    if len(b) % wsize != 0:
      raise ValueError("Invalid block size")
    return [
        int.from_bytes(b[i:i + wsize], "little")
        for i in range(0, len(b), wsize)
    ]

  def pack(self, *values):
    wsize = self.block_size_in_bytes // 2
    return b"".join(x.to_bytes(wsize, "little") for x in values)

  def expand_key(self, key: bytes, rounds: int) -> list:
    k = self.unpack(key)
    b = k[0]
    k = k[1:]
    round_keys = [b]
    for i in range(rounds - 1):
      a = k[0]
      a, b = r(a, b, i, self.word_size)
      k = k[1:] + [a]
      round_keys.append(b)
    return round_keys

  def encrypt_block(self, pt: bytes) -> bytes:
    if len(pt) != self.block_size_in_bytes:
      raise ValueError("Invalid block size")
    y, x = self.unpack(pt)
    for rk in self.round_keys:
      x, y = r(x, y, rk, self.word_size)
    return self.pack(y, x)

  def decrypt_block(self, ct: bytes) -> bytes:
    if len(ct) != self.block_size_in_bytes:
      raise ValueError("Invalid block size")
    y, x = self.unpack(ct)
    for rk in self.round_keys[::-1]:
      x, y = rinv(x, y, rk, self.word_size)
    return self.pack(y, x)


class Speck128(Speck):
  key_sizes_in_bytes = (16, 24, 32)
  block_size_in_bytes = 16
  rounds = {2: 32, 3: 33, 4: 34}


class Speck96(Speck):
  key_sizes_in_bytes = (12, 18)
  block_size_in_bytes = 12
  rounds = {2: 28, 3: 29}


class Speck64(Speck):
  key_sizes_in_bytes = (12, 16)
  block_size_in_bytes = 8
  rounds = {3: 26, 4: 27}


class Speck48(Speck):
  key_sizes_in_bytes = (9, 12)
  block_size_in_bytes = 6
  rounds = {3: 22, 4: 23}


# All the test vectors are apparently in little endian order.
speck_ktv = {
    "Speck32/64": [{
        "key": "1918 1110 0908 0100",
        "pt": "6574 694c",
        "ct": "a868 42f2"
    }],
    "Speck48/72": [{
        "key": "121110 0a0908 020100",
        "pt": "20796c 6c6172",
        "ct": "c049a5 385adc"
    }],
    "Speck48/96": [{
        "key": "1a1918 121110 0a0908 020100",
        "pt": "6d2073 696874",
        "ct": "735e10 b6445d"
    }],
    "Speck64/96": [{
        "key": "13121110 0b0a0908 03020100",
        "pt": "74614620 736e6165",
        "ct": "9f7952ec 4175946c"
    }],
    "Speck64/128": [{
        "key": "1b1a1918 13121110 0b0a0908 03020100",
        "pt": "3b726574 7475432d",
        "ct": "8c6fa548 454e028b"
    }],
    "Speck96/96": [{
        "key": "0d0c0b0a0908 050403020100",
        "pt": "65776f68202c 656761737520",
        "ct": "9e4d09ab7178 62bdde8f79aa"
    }],
    "Speck96/144": [{
        "key": "151413121110 0d0c0b0a0908 050403020100",
        "pt": "656d6974206e 69202c726576",
        "ct": "2bf31072228a 7ae440252ee6"
    }],
    "Speck128/128": [{
        "key": "0f0e0d0c0b0a0908 0706050403020100",
        "pt": "6c61766975716520 7469206564616d20",
        "ct": "a65d985179783265 7860fedf5c570d18"
    }],
    "Speck128/192": [{
        "key": "1716151413121110 0f0e0d0c0b0a0908 0706050403020100",
        "pt": "7261482066656968 43206f7420746e65",
        "ct": "1be4cf3a13135566 f9bc185de03c1886"
    }],
    "Speck128/256": [{
        "key": "1f1e1d1c1b1a1918 1716151413121110"
               "0f0e0d0c0b0a0908 0706050403020100",
        "pt": "65736f6874206e49 202e72656e6f6f70",
        "ct": "4109010405c0f53e 4eeeb48d9c188f43"
    }],
}


def test_ktv(alg, clazz, debug=True):
  for t in speck_ktv[alg]:
    key = bytes.fromhex(t["key"])[::-1]
    pt = bytes.fromhex(t["pt"])[::-1]
    ct = bytes.fromhex(t["ct"])[::-1]
    cipher = clazz(key)
    c2 = cipher.encrypt_block(pt)
    p2 = cipher.decrypt_block(c2)
    if debug:
      # Just print the plaintext to check byte order
      print(alg, pt)
    assert c2 == ct
    assert p2 == pt


def test():
  for alg in speck_ktv:
    id = alg.split("/")[0]
    if id == "Speck128":
      test_ktv(alg, Speck128)
    elif id == "Speck96":
      test_ktv(alg, Speck96)
    elif id == "Speck64":
      test_ktv(alg, Speck64)
    elif id == "Speck48":
      test_ktv(alg, Speck48)
    elif id == "Speck32":
      # not implemented
      pass
    else:
      raise ValueError("unknown algorithm:" + alg)


if __name__ == "__main__":
  test()
