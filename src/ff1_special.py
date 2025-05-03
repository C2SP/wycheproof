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

import ff1
import util
import prand
import flag
from typing import Optional
from dataclasses import dataclass


@dataclass
class EdgeCase:
  radix: int
  key: bytes
  tweak: bytes
  pt: list[int]
  comment: str
  flags: list[flag.Flag]

def generate_state(cipher,
                   radix: int,
                   key: bytes,
                   tweak: bytes,
                   n: int):
  """Generates inputs for a FPE with edge case states.

  Args:
    cipher: e.g. ff1.AesFf1
    radix: the radix
    key: a key
    tweak: a tweak
    n: message size
  """
  edge_case_state = flag.Flag(
      label="EdgeCaseState",
      bug_type=flag.BugType.EDGE_CASE,
      description="FF1 requires integer arithmetic of various sizes. "
      "This test vector contains values such that edge cases are reached "
      "during encryption and decryption. The goal of the test vector "
      "is to check for incorrect integer arithmetic e.g., because of "
      "integer overflows.")
  if not issubclass(cipher, ff1.Ff1):
    raise ValueError("not supported")
  fpe = cipher(key, radix)
  rounds = fpe.rounds
  for r in [0, rounds//2, rounds//2 + 1, rounds]:
    u = n // 2
    v = n - u
    if r % 2:
      u, v = v, u
    max_a = radix ** u - 1
    max_b = radix ** v - 1
    s = 2 ** (max_a.bit_length() - 1)
    t = 2 ** (max_b.bit_length() - 1)
    for num_a, num_b, comment in [
        (0, 0, "minimal integer values"),
        (max_a, max_b, "maximal integer values"),
        (s, t, "powers of two"),
        (s - 1, t - 1, "integers with large hamming weight"),
    ]:
      A = fpe.num_str(num_a, u)
      B = fpe.num_str(num_b, v)
      # Sanity check, that the state is correct
      pt = fpe.pt_with_state(tweak, r, A, B)
      d = fpe.states(tweak, pt)[r]
      assert d[0] == num_a
      assert d[1] == num_b

      if r == 0:
        rstr = "plaintext"
      elif r == rounds:
        rstr = "ciphertext"
      else:
        rstr = f"round {r}"
      yield EdgeCase(
          radix=radix,
          key=key,
          tweak=tweak,
          pt=pt,
          comment=f"{comment} in {rstr}",
          flags=[edge_case_state])

def generate_extreme_y(cipher,
                       radix: int,
                       key: bytes,
                       n: int):
  edge_case_prf = flag.Flag(
      label="EdgeCasePrf",
      bug_type=flag.BugType.EDGE_CASE,
      description="FF1 computes a pseudorandom function, converts the result "
      "into an integer y, which is then reduced modulo radix**v, where v is "
      "the size of the longer block in the Feistel structure. "
      "This test vector contains cases where the value y is an edge case. "
      "The goal of the test vector is to check for arithmetic errors such as "
      "integer overflow or incorrect modular reduction.")
  if not issubclass(cipher, ff1.Ff1):
    raise ValueError("not supported")
  fpe = cipher(key, radix)
  rounds = fpe.rounds
  u, v, b, d = fpe.get_sizes(n)
  block_size = fpe.block_size()
  max_y = 256 ** d - 1
  if d <= block_size:
    for y, doc_y in [(0, "y = 0"),
                       (1, "y = 1"),
                       (max_y, "y is maximal"),
                       (max_y - max_y % radix,
                        "y is edge case for modular reduction"),
                       (max_y - max_y % (radix**v) - 1,
                        "y is maximal after modular reduction"),]:
      for i in range(2000):
        id = b"%s%d%d" % (key, radix, i)
        if d == block_size:
          tweak_prefix = prand.randbytes(
              block_size, seed=b"12lk123hs", label=id)
        else:
          tweak_prefix = bytes()
        random_block = prand.randbytes(block_size, seed=b"98127sjh13", label=id)
        r, num_b, tweak = fpe.invert_round_function(y, n, tweak_prefix, random_block)
        if r % 2:
          len_a, len_b = v, u
        else:
          len_a, len_b = u, v
        if r < 10 and num_b < radix ** len_b:
          y2 = fpe.round_function(r, num_b, tweak, n)
          range_a = radix ** len_a
          if len_a == 1:
            range_a_doc = f"radix"
          else:
            range_a_doc = f"radix**{len_a}"
          set_a = {(0, "a = 0"),
                   (1, "a = 1"),
                   (range_a - 1, "a is maximal"),
                   (2 ** ((range_a - 1).bit_length() - 1), "a has large Hamming weight"),
                   (-y % range_a, f"(y + a) % {range_a_doc} == 0"),
                   ((-1 - y) % range_a, f"(y + a) % {range_a_doc} is maximal"),}
          for num_a, doc_a in sorted(set_a):
            A = fpe.num_str(num_a, len_a)
            B = fpe.num_str(num_b, len_b)
            pt = fpe.pt_with_state(tweak, r, A, B)

            # Sanity check
            state = fpe.states(tweak, pt)[r]
            assert state[0] == num_a
            assert state[3] == y

            yield EdgeCase(
                radix=radix,
                key=key,
                tweak=tweak,
                pt=pt,
                comment=f"{doc_y} and {doc_a} in round {r}",
                flags=[edge_case_prf])
          break
  else:
    # d > block_size
    pass
