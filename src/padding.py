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

class Padding:
  """This is an abstract base class for paddings."""

  def pad(msg: bytes) -> bytes:
    raise NotImplementedError("Must be overriden by subclass")

  def unpad(msg: bytes) -> bytes:
    raise NotImplementedError("Must be overriden by subclass")


class NoPadding(Padding):

  def __init__(self, block_cipher):
    pass

  def pad(self, msg: bytes) -> bytes:
    return msg

  def unpad(self, msg: bytes) -> bytes:
    return msg


class Pkcs8Padding(Padding):

  def __init__(self, block_cipher):
    block_size = block_cipher.block_size_in_bytes
    if block_size < 1 or block_size > 256:
      raise ValueError("Invalid block size")
    self.block_size = block_size

  def pad(self, msg: bytes) -> bytes:
    pad_len = self.block_size - len(msg) % self.block_size
    return msg + bytes([pad_len]) * pad_len

  def unpad(self, msg: bytes) -> bytes:
    if len(msg) == 0:
      raise ValueError("can't unpad empty message")
    pad_len = msg[-1]
    if pad_len > self.block_size or pad_len < 1 or pad_len > len(msg):
      raise ValueError("invalid pad length")
    padding = msg[-pad_len:]
    if padding != bytes([pad_len] * pad_len):
      raise ValueError("invalid PKCS8 padding")
    return msg[:-pad_len]


class Pkcs5Padding(Pkcs8Padding):
  """PKCS5 padding

  PKCS5 padding is the same as PKCS8 padding with the only difference
  that strictly speaking PKCS5 padding is limited to 8 byte block ciphers.
  """
