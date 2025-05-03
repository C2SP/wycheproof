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

from typing import Optional

# A Keccack state. This is typically 200 bytes or 1600 bits
State = bytes

# A Keccack state as a two dimensional array of integers.
# This is typically a 5*5 array of 64-bit integers.
Lanes = list[list[int]]

def rotate_left(x: int, n: int, bits: int) -> int:
  """Rotates an integer to the left.
  
  Args:
    x: the integer to rotate
    n: the size of the integer in bits
    bits: the number of bits to rotate.
  Returns:
    the rotated integer
  """
  assert 0 <= n < bits
  return ((x >> (bits - n)) + (x << n)) % (1 << bits)
  
def state_to_lanes(state: State, wb: int) -> Lanes:
  """Converts a state to lanes.
  
  Args:
    state: the state
    wb: the length of the lanes in bytes. This is typically 8.
  """
  lanes = []
  for x in range(5):
    tmp = []
    for y in range(5):
      idx = 5 * y + x
      lane = int.from_bytes(state[idx * wb: (idx+1) * wb], "little")
      tmp.append(lane)
    lanes.append(tmp)
  return lanes
  
def lanes_to_state(lanes: Lanes, wb: int) -> State:
  """Converts an array of lanes to a state.

  Args:
    lanes: the lanes
    wb: the length of a lane in bytes. This is typically 8.
  """
  state = bytearray()
  for y in range(5):
    for x in range(5):
      state += lanes[x][y].to_bytes(wb, "little")
  return bytes(state)

# Round constants for w=64 and rounds=24
ROUND_CONSTANTS_W64 = [0x1, 0x8082, 0x800000000000808a, 0x8000000080008000,
     0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
     0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b, 0x800000000000008b,
     0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
     0x8000000000000080, 0x800a, 0x800000008000000a, 0x8000000080008081,
     0x8000000000008080, 0x80000001, 0x8000000080008008]

def KeccakF(state: State, rounds: Optional[int] = None) -> State:
    """The Keccak-F function for a 1600-bit state.
  
    Args:
      state: the state before the F functions
      rounds: the number of rounds. This is typically 24. Some Keyccak
        variants use 12 rounds.
    """
    if rounds is None:
      rounds = 24
    # Checks the preconditions
    assert len(state) == 200
    assert rounds <= len(ROUND_CONSTANTS_W64)
    wb = len(state) // 25
    w = 8 * wb
    lanes = state_to_lanes(state, wb)
    for rc in ROUND_CONSTANTS_W64[-rounds:]:
      # theta
      C = [lane[0] ^ lane[1] ^ lane[2] ^ lane[3] ^ lane[4] for lane in lanes]
      for x in range(5):
        Dx = C[(x + 4) % 5] ^ rotate_left(C[(x + 1) % 5], 1, w)
        for y in range(5):
          lanes[x][y] ^= Dx
      # rho and pi
      x, y = 1, 0
      current = lanes[x][y]
      for t in range(24):
          x, y = y, (2 * x + 3 * y) % 5
          rot = (t + 1) * (t + 2) // 2 % w
          current, lanes[x][y] = lanes[x][y], rotate_left(current, rot, w)
      # chi
      a = [row.copy() for row in lanes]
      for x in range(5):
        row1 = a[(x + 1) % 5]
        row2 = a[(x + 2) % 5]
        for y in range(5):
          lanes[x][y] ^= ~row1[y] & row2[y]
      # iota
      lanes[0][0] ^= rc
    return lanes_to_state(lanes, wb)

def Keccak(c: int, data: bytes, postfix: int, output_size: int, rounds: Optional[int]=None) -> bytes:
  w = 1600
  rate = w - c
  if rate % 8:
    raise NotImplementedError("Expecting r to be a multiple of 8")
  rate_in_bytes = rate // 8
  padding = bytearray(rate_in_bytes - len(data) % rate_in_bytes)
  padding[0] ^= postfix
  padding[-1] ^= 0x80
  data += padding
  state = bytes(w // 8)
  for offset in range(0, len(data), rate_in_bytes):
    if offset > 0:
      state = KeccakF(state, rounds)
    xored = bytes(state[i] ^ data[offset + i] for i in range(rate_in_bytes))
    state = xored + state[rate_in_bytes:]
  res = bytearray()
  while len(res) < output_size:
    state = KeccakF(state, rounds)
    res += state[:rate_in_bytes]
  return bytes(res[:output_size])
  
def SHA3_224(data: bytes):
    return Keccak(448, data, 0x06, 224 // 8)

def SHA3_256(data: bytes):
    return Keccak(512, data, 0x06, 256 // 8)

def SHA3_384(data: bytes):
    return Keccak(768, data, 0x06, 384 // 8)

def SHA3_512(data: bytes):
    return Keccak(1024, data, 0x06, 512 // 8)

def SHAKE128(data: bytes, output_size: int):
    return Keccak(256, data, 0x1f, output_size)

def SHAKE256(data: bytes, output_size: int):
    return Keccak(512, data, 0x1f, output_size)

# From pysha3
def KECCAK_224(data: bytes):
  return Keccak(448, data, 0x01, 224 // 8)

def KECCAK_256(data: bytes):
  return Keccak(512, data, 0x01, 256 // 8)

def KECCAK_384(data: bytes):
    return Keccak(768, data, 0x01, 384 // 8)

def KECCAK_512(data: bytes):
    return Keccak(1024, data, 0x01, 512 // 8)

# cSHAKE and KMAC
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

# ===== FIPS SP 800-185
def left_encode(x : int) -> bytes:
  size = max(1, (x.bit_length() + 7) // 8)
  if size > 255:
    raise ValueError("Input to large")
  return bytes([size]) + x.to_bytes(size, "big")

def right_encode(x : int) -> bytes:
  size = max(1, (x.bit_length() + 7) // 8)
  if size > 255:
    raise ValueError("Input to large")
  return x.to_bytes(size, "big") + bytes([size])

def encode_string(s: bytes) -> bytes:
  return left_encode(len(s) * 8) + s

def bytepad(s: bytes, w: int):
  z = left_encode(w) + s 
  return z + bytes(-len(z) % w)

def cSHAKE128(X: bytes, L: int, N: bytes, S: bytes):
  if not N and not S:
    return SHAKE128(X, L)
  else:
    return Keccak(256, bytepad(encode_string(N) + encode_string(S), 168) + X, 0x4, L)
    
def cSHAKE256(X: bytes, L: int, N: bytes, S: bytes):
  if not N and not S:
    return SHAKE256(X, L)
  else:
    return Keccak(512, bytepad(encode_string(N) + encode_string(S), 136) + X, 0x4, L)

def KMAC128(K: bytes, X: bytes, L: int, S: bytes = b"") -> bytes:
  """Computes KMAC128.
  
  Args:
    K: the key
    X: the main input
    L: the length of the output in bytes
    S: an optional customization string
  """
  new_x = bytepad(encode_string(K), 168) + X + right_encode(L * 8)
  return cSHAKE128(new_x, L, b"KMAC", S)

def KMAC256(K: bytes, X: bytes, L: int, S: bytes = b"") -> bytes:
  new_x = bytepad(encode_string(K), 136) + X + right_encode(L * 8)
  return cSHAKE256(new_x, L, b"KMAC", S)
  
def KMACXOF128(K: bytes, X: bytes, L: int, S: bytes):
  new_x = bytepad(encode_string(K), 168) + X + right_encode(0)
  return cSHAKE128(new_x, L, b"KMAC", S)

def KMACXOF256(K: bytes, X: bytes, L: int, S: bytes) -> bytes:
  new_x = bytepad(encode_string(K), 136) + X + right_encode(0)
  return cSHAKE256(new_x, L, b"KMAC", S)

# ===== KangarooTwelve
# https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/

# This is the code from the reference. bytes_encode(0) returns bytes([0]).
# NIST's definition would return bytes([0,1])
def right_encode_k12(x : int) -> bytes:
  size = (x.bit_length() + 7) // 8
  assert size <= 255
  return x.to_bytes(size, "big") + bytes([size])

def KangarooTwelve(data: bytes, customization_string: bytes, output_size: int):
  B = 8192
  c = 256
  rounds = 12
  S = data + customization_string + right_encode_k12(len(customization_string))

  if len(S) <= B:
    return Keccak(c, S, 0x07, output_size, rounds)
  else:
    Si = [S[i: i + B] for i in range(B, len(S), B)]
    CVi = b"".join(Keccak(c, block, 0x0B, c//8, rounds) for block in Si)
    node_star = (S[:B] + bytes([3, 0, 0, 0, 0, 0, 0, 0]) + CVi
          + right_encode_k12(len(Si)) + bytes([0xff, 0xff]))
    return Keccak(c, node_star, 0x06, output_size, rounds)
    
def HopMAC(key: bytes, msg: bytes, customization_str: bytes, output_size: int):
  digest = KangarooTwelve(message, customization_str, 32)
  return KangarooTwelve(key, digest, L)

def TurboShake128(message: bytes, separationByte: int, output_size: int):
  return Keccak(256, message, separationByte, output_size, rounds=12)

def TurboShake256(message: bytes, separationByte: int, output_size: int):
  return Keccak(512, message, separationByte, output_size, rounds=12)

