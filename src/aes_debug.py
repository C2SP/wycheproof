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

# A simple tool for debuging faulty AES encryptions.

import aes_util

def steps_encrypt(aes, pt_block: bytes):
  rk = aes.round_keys_enc
  rounds = aes.rounds
  res = []
  s = aes_util._xor(pt_block, rk[0])
  res.append(s)
  for r in range(1, rounds):
    s = aes_util.aes_enc(s, rk[r])
    res.append(s)
  s = aes_util.aes_enc_last(s, rk[-1])
  res.append(s)
  return res

def steps_decrypt(aes, ct_block: bytes):
  rk = aes.round_keys_dec
  rounds = aes.rounds
  res = []
  s = aes_util._xor(ct_block, rk[0])
  res.append(s)
  for r in range(1, rounds):
    s = aes_util.aes_dec(s, rk[r])
    res.append(s)
  s = aes_util.aes_dec_last(s, rk[-1])
  res.append(s)
  return res

def steps_encrypt_all(aes, pt_block: bytes):
  """Returns the results after each single step during encryption.

  As single step counts xor, shift_row, mix_column or sbox.

  Args:
    aes: a block cipher
    pt_blocks: a plaintext block
  """
  rk = aes.round_keys_enc
  rounds = aes.rounds
  res = [pt_block]
  s = aes_util._xor(pt_block, rk[0])
  res.append(s)
  for r in range(1, rounds):
    s = aes_util.shift_rows(s)
    res.append(s)
    s = aes_util.sbox(s)
    res.append(s)
    s = aes_util.aes_mc(s)
    res.append(s)
    s = aes_util._xor(s, rk[r])
    res.append(s)
  s = aes_util.shift_rows(s)
  res.append(s)
  s = aes_util.sbox(s)
  res.append(s)
  s = aes_util._xor(s, rk[rounds])
  res.append(s)
  return res

def steps_decrypt_all(aes, ct_block: bytes):
  """Returns the results after each single step during decryption.

  This implemenation is inverts the encryption. It does not simulate
  decryption with AES-NI instructions (I.e. decryption switches some
  steps that commute).
  """
  rk = aes.round_keys_enc
  rounds = aes.rounds
  res = [ct_block]
  s = aes_util._xor(ct_block, rk[rounds])
  res.append(s)
  s = aes_util.inverse_sbox(s)
  res.append(s)
  s = aes_util.inverse_shift_rows(s)
  res.append(s)
  for r in range(rounds - 1, 0, -1):
    s = aes_util._xor(s, rk[r])
    res.append(s)
    s = aes_util.aes_imc(s)
    res.append(s)
    s = aes_util.inverse_sbox(s)
    res.append(s)
    s = aes_util.inverse_shift_rows(s)
    res.append(s)
  s = aes_util._xor(s, rk[0])
  res.append(s)
  return res

def debug(key: bytes, pt_block: bytes, ct_block: bytes):
  """Tries to detect potential bugs in an encryption.

  Args:
    key: the key used to encrypt a block
    pt_block: the plaintext block that was encrypted
    ct_block: the faulty ciphertext block.
  """
  aes = aes_util.Aes(key)
  steps_enc = steps_encrypt(aes, pt_block)
  steps_cmp = steps_encrypt(aes, aes.decrypt_block(ct_block))
  
  for e,d in zip(steps_enc, steps_cmp):
    print(e.hex(), d.hex(), aes_util._xor(e, d).hex())

if __name__ == "__main__":
  k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
  e = bytes.fromhex("00112233445566778899aabbccddeeff")
  d = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
  debug_old(k, e, d)
  print()
  debug(k, e, d)

