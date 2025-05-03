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
import collections
import hashlib
import inspect
import sys
import types
import typing


def check_python_version():
  """Checks the python version.

  Currently python3.8 is required

  Some reasons for restricting the version are:
   - type hints: @type_check can be used to check types at runtime.
        the implementation depends on the class structure in the module typing.
        This class structure changes frequently.
   - hashlib: the code uses a number of hash functions: SHA-3, SHA-512-256,
        shake. These functions are not available in earlier versions.
   - pow(a, -1, b) can be used to compute modular inverses. This has been
        added in version 3.8.
   - the walrus operator is used in the code. This has been added in version
     3.8
  """
  assert (sys.version_info.major, sys.version_info.minor) >= (3, 8)


def deprecated(comment, cap=10):
  """Decorator that prints a warning when the decorated function is used.

     Example:
     @deprecated("Use new_function instead of old_function")
     def old_function(x):
       ...
  """
  def decorator(func):
    deprecated_count = 0
    def wrapper(*args, **kwargs):
      nonlocal deprecated_count
      deprecated_count += 1
      if deprecated_count <= cap:
        print(comment)
      return func(*args, **kwargs)
    return wrapper
  return decorator

def type_check(func):
  """A decorator for simple type checks at run-time.

     So far this only works for simple types, Any, Tuple, Union and Optional.
     The return type can be a simple generator.
  """
  if skip_type_check:
    return func
  type_hints = typing.get_type_hints(func)
  func_args = inspect.getfullargspec(func)[0]

  def has_any_type(val, type_list):
    return any(has_type(val, t) for t in type_list)

  def has_type(val, type_hint):
    if type_hint == typing.Any:
      return True
    elif (isinstance(type_hint, typing._GenericAlias) or
        isinstance(type_hint, types.GenericAlias)):
      orig = type_hint.__origin__
      if orig == typing.Union:
        return has_any_type(val, type_hint.__args__)
      if orig == list:
        if not isinstance(val, list):
          return False
        return all(has_any_type(x, type_hint.__args__) for x in val)
      if orig == tuple:
        if not isinstance(val, tuple):
          return False
        if len(val) != len(type_hint.__args__):
          return False
        return all(has_type(v, t) for v, t in zip(val, type_hint.__args__))
    elif isinstance(type_hint, type):
      return isinstance(val, type_hint)
    raise TypeError("unknown type:", type_hint)

  def check_type(name, val):
    if name in type_hints:
      type_hint = type_hints[name]
      if not has_type(val, type_hint):
        wrong_type = f"{name} is of type: {type(val)} expected: {type_hint}\n"
        wrong_type += f"val:{repr(val)}"
        raise TypeError(wrong_type)

  def check_generator(name, val):
    """Gets a generator and returns a type checked generator"""
    if name not in type_hints:
      yield from val
    else:
      type_hint = type_hints[name]
      # TODO: typing.Generator is deprecated since 3.9
      if isinstance(type_hint, typing._GenericAlias):
        raise TypeError("typing.Generator and typing.Iterator are deprecated")
      if (isinstance(type_hint, typing.GenericAlias) and
          (type_hint.__origin__ == collections.abc.Iterator or
           type_hint.__origin__ == collections.abc.Generator)):
        res_type = type_hint.__args__[0]
        for y in val:
          if has_type(y, res_type):
            yield y
          else:
            raise TypeError("iterator element is of type %s expected: %s\nval:%s"
                        %(type(y), res_type, repr(y)))
      else:
        raise TypeError("%s is of type %s expected: %s\nval:%s"
                         %(name, type(val), type_hint, repr(val)))

  def wrapper(*args, **kwargs):
    for i, val in enumerate(args):
      check_type(func_args[i], val)
    for n, val in kwargs.items():
      check_type(n, val)
    res = func(*args, **kwargs)
    # Allowing generators as return type
    if isinstance(res, types.GeneratorType):
      return check_generator("return", res)
    else:
      check_type("return", res)
      return res

  if func.__doc__:
    wrapper.__doc__ = func.__doc__
  return wrapper


skip_type_check=False
if sys.version_info.minor < 7:
  skip_type_check = True

# TODO: convert into types
class IntRangeMeta(type):
  def __instancecheck__(self, val):
    return isinstance(val, int) and self.lower <= val < self.upper

class Uint8(metaclass = IntRangeMeta):
  lower = 0
  upper = 2**8

class Uint32(metaclass = IntRangeMeta):
  lower = 0
  upper = 2**32

class Uint64(metaclass = IntRangeMeta):
  lower = 0
  upper = 2**64

class Uint128(metaclass = IntRangeMeta):
  lower = 0
  upper = 2**128

class FixedLengthBytesMeta(type):
  def __instancecheck__(self, val):
    return isinstance(val, bytes) and len(val) == self.size

class Bytes16(metaclass=FixedLengthBytesMeta):
  size = 16


def as_bytes(s: typing.Union[bytes, bytearray, str]) -> bytes:
  """Converts a string or bytearray into bytes.

  This function is a leftover from python2 to python3 conversion
  and is deprecated.

  Args:
    s: the input to convert

  Returns:
    the input as bytes
  """
  if isinstance(s, str):
    return bytes(ord(x) for x in s)
  elif isinstance(s, bytearray):
    return bytes(s)
  elif isinstance(s, bytes):
    return s
  else:
    raise Exception("Not implemented")


def _uint2bytes(w: int,
                length: typing.Optional[int],
                allow_truncate: bool = False):
  """Converts an unsigned integer to a bigendian representation

     using length bytes.

  Args:
    w: the integer to convert
    length: the length of the result. If None then the minimal length will be
      used.
    allow_truncate: allows to truncate the integer if it is too large.
  """
  if w < 0:
    raise ValueError("w must be positive")
  res = []
  if length is None:
    while True:
      res.append(w % 256)
      w >>= 8
      if w == 0: break
  else:
    for _ in range(length):
      res.append(w % 256)
      w >>= 8
  if w != 0 and not allow_truncate:
    raise ValueError("w is too large")
  return bytes(res[::-1])

def bytes2urlsafe64(b: bytes) -> str:
  """Encodes a byte sequence into urlsafe hexadecimal encoding.

  Args:
    b: the bytes to convert

  Returns:
    the urlsave encoded string
  """
  encoded = base64.urlsafe_b64encode(b).replace(b"=", b"")
  return encoded.decode("ascii")

def uint2urlsafe64(w: int, length: typing.Optional[int] = None) -> str:
  """Encoded a byte sequence in urlsave hexadecimal encoding.

  Args:
    w: the integer to convert
    length: the size of the integer in bytes. If length is None then the minimal
      number of bytes is used.

  Returns:
    the encoded integer
  """
  return bytes2urlsafe64(_uint2bytes(w, length))

@type_check
def hash(hash_name: str, message: bytes) -> bytes:
  """Convenience function for computing a hash.

  Args:
    hash_name: the name of teh hash.
    message: the message to hash

  Returns:
    the hash value
  """
  if hash_name == "MD5":
    md = hashlib.md5()
  elif hash_name == "SHA-1":
    md = hashlib.sha1()
  elif hash_name == "SHA-224":
    md = hashlib.sha224()
  elif hash_name == "SHA-256":
    md = hashlib.sha256()
  elif hash_name == "SHA-384":
    md = hashlib.sha384()
  elif hash_name == "SHA-512":
    md = hashlib.sha512()
  # Requires python 3.6
  elif hash_name == "SHA3-224":
    md = hashlib.sha3_224()
  elif hash_name == "SHA3-256":
    md = hashlib.sha3_256()
  elif hash_name == "SHA3-384":
    md = hashlib.sha3_384()
  elif hash_name == "SHA3-512":
    md = hashlib.sha3_512()
  # Requires python 3.7
  # OID is defined in RFC 8017.
  # The identifier is id-sha512-224.
  # The name is name of the algorithm used is SHA-512/224.
  # jdk also uses the algorithm name SHA-512/224.
  elif hash_name == "SHA-512/224":
    md = hashlib.new("sha512-224")
  elif hash_name == "SHA-512/256":
    md = hashlib.new("sha512-256")
  # When used as a hash SHAK128 has 32 bytes of output
  # and SHAKE256 has 64 bytes of output
  elif hash_name == "SHAKE128":
    return shake(hash_name, message, 32)
  elif hash_name == "SHAKE256":
    return shake(hash_name, message, 64)
  else:
    raise ValueError("Unknown hash:" + hash_name)
  md.update(message)
  return md.digest()


def digest_size(hash_name: str) -> int:
  """Returns the digest size of a hash function.

  Args:
    hash_name: the name of the hash

  Returns:
    the length of the digest in bytes
  """
  return len(hash(hash_name, b""))


@type_check
def shake(name: str, message: bytes, size: int) -> bytes:
  """Computes the SHAKE hash and returns size bytes.

  Args:
    name: the name of the function
    message: the message to hash
    size: the size of the output in bytes

  Returns:
    the SHAKE hash of message
  """
  if name == "SHAKE128":
    md = hashlib.shake_128()
  elif name == "SHAKE256":
    md = hashlib.shake_256()
  else:
    raise ValueError("Unknown algorithm:" + name)
  md.update(message)
  return md.digest(size)


if __name__ == "__main__":
  if skip_type_check:
    print("runtime type checking is off")
