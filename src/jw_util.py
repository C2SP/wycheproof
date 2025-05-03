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

def encode(b: bytes) -> bytes:
  return base64.urlsafe_b64encode(b).rstrip(b"=")

def decode(s: bytes) -> bytes:
  return base64.urlsafe_b64decode(s + b"="*(-len(s)%4))

def encode_str(s: str) -> bytes:
  return encode(s.encode("utf8"))

def decode_str(s: bytes) -> str:
  return decode(s).decode("utf8")

def encode_int(b: int) -> bytes:
  if b < 0:
    raise ValueError("Cannot encode a negative integer")
  size = (b.bit_length() + 7) // 8
  return encode(b.to_bytes(size, "big"))

def decode_int(s: bytes) -> int:
  return int.from_bytes(deocde(s), "big")


