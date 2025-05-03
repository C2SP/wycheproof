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

# python3
# This file is a heuristic implementation that tries to extract as
# many public keys as possible from source files.
import asn
import asn_parser
import base64
import collections
import json
import oid
import oid_util
import typing
import asn1crypto.x509

# Other patterns:
# Hexadecimal strings containing OIDs 217 samples (A large fractions is tests)
#    e.g. 06092a864886f70d010101
# Hexadecimal strings with ":"
#    e.g. 2a:86:48:86:f7:0d:01:01:01   6 samples
# Functions calls:
#    e.g. new X509EncodedKeySpec(<arg>)
#    needs a static analyzer to track arguments.

KEY_HUNT = "../../keyhunt"
SAMPLES = "samples"

def try_cleanup(base64url: str) -> str:
  urlchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
  res = []
  escape = False
  inside = True
  for i,c in enumerate(base64url):
    if escape:
      escape = False
      if c == 'n':
        continue
      if c == '\\':
        # Sometimes \n is escaped twice as \\n
        escape = True
        continue
    elif c == '\\':
      escape = True
      continue
    if c in '"\'':
      inside = not inside
    elif c in ' \n\t':
      continue
    elif inside:
      if c in urlchars:
        res.append(c)
      else:
        raise ValueError("can't parse base64url at %s %s" % (i, c))
    else:
      continue
  if not res:
    # These are generally cases of code that reads or writes PEM files:
    # E.g.
    # header = "-----BEGIN PUBLIC KEY-----"
    # ...
    # footer = "-----END PUBLIC KEY-----"
    raise ValueError("everything escaped")
  return ''.join(res)

def extract_pem(
    s: str,
    debug: bool = False,
    fn: str = None,
    stats:dict = None):
  '''Tries to extract a list of PEM encoded keys from s.
     Yields the ASN.1 encoded strings. Basically yields anything
     between "-----BEGIN <something>-----" and
     "-----END " that is base64 encoded.
     
     Args:
       s: the string to parse
       debug: print the string that cannot be parsed
  '''
  pos = 0
  maxsize = 8000
  assert isinstance(s, str)
  while True:
    start = s.find("-----BEGIN ", pos)
    pos = start + 11
    if start == -1:
      break
    start_content = s.find("-----", pos)
    if start_content == -1:
      break
    header = s[pos: start_content]
    pos = start_content + 5
    stop = s.find("-----END ", pos)
    if stop == -1:
      break
    stop_pem = s.find("-----", stop + 8)
    if stop_pem == -1:
      break
    b64 = s[pos : stop]
    pem = s[start : stop_pem]
    try:
      b64c = try_cleanup(b64)
      asn = base64.b64decode(b64c)
      yield header, pem, asn
    except Exception as ex:
      # This is not a PEM key or the code doesn't know to handle it.
      # Tries to find a reason.
      if b64.find("...") >= 0 or b64.find(chr(0x2026)) >= 0:
        reason = "PEM with ellipsis"
      elif b64.find("Version:") >= 0:
        reason = "PEM with old format"
      elif b64.find("// ") >= 0:
        reason = "PEM in comments"
      else:
        # TODO: find additional reasons
        reason = "not base64"

      if reason is not None:
        stats[reason] += 1
      else:
        stats["PEM with unexplained b64 parse error"] += 1
        if debug:
          print(str(ex), 'cannot parse', b64)
          if fn is not None:
            print('file:', fn)


def get_algorithm_name(oid_bytes: bytes):
  o = oid.frombytes(oid_bytes)
  if oid_util.lookup(o):
    return o.description
  return "Oid:" + str(oid.frombytes(oid_bytes))

def try_extract_key(asn_struct):
  if not isinstance(asn_struct, list) or len(asn_struct) < 2:
    return
  alg = asn_struct[0]
  if not isinstance(alg, list) or len(alg) == 0:
    return
  alg_oid = alg[0]
  if not isinstance(alg_oid, asn.Element):
    return
  if alg_oid.tag != asn.OBJECT_IDENTIFIER:
    return
  oid_hex = alg_oid.val.hex()
  key = {}
  key["asn"] = asn.encode(asn_struct).hex()
  try:
    algorithm_name = get_algorithm_name(alg_oid.val)
    key["algorithm"] = algorithm_name
  except Exception as ex:
    key["algorithm"] = 'undefined'
    key["error"] = "invalid oid:" + oid_hex
    return key
  # RsaEncryption
  try:
    if oid_hex == "2a864886f70d010101":
      bitstring = asn_struct[1]
      if isinstance(bitstring, asn.AsnComposition):
        val = bitstring.val
      elif isinstance(bitstring, asn.AsnElement):
        val = bitstring.val[1:]
      else:
        raise ValueError("bitstring has type" + str(type(bitstring)))
      if bitstring.tag != asn.BIT_STRING:
        raise ValueError("tag is :" + bitstring.tag)
      val = asn_parser.parse(val, strict=False)
      key["n"] = str(val[0])
      key["e"] = str(val[1])
  except Exception as ex:
    key["error"] = str(ex)
  return key

def extract_keys_from_struct(val):
  if isinstance(val, list):
    key = try_extract_key(val)
    if key is not None:
      yield key
    else:
      for v in val:
        yield from extract_keys_from_struct(v)

def print_samples(fn: str, samples: dict):
  with open(fn, 'w') as fp:
    fp.write("SAMPLES = {")
    for k in sorted(samples):
      v = samples[k]
      fp.write(f'  ({repr(k)}:\n"""{v}"""),\n')
    fp.write("}")

def print_dict(title: str, d:dict):
  print(f"----- {title} -----")
  for alg, cnt in d.items():
    print(alg, cnt)

# Currently we get:
# 2a8648ce380401 32  DSA
# 2a8648ce3d0201 119 ECPublicKey
# 2a864886f70d010101 361 RSAEncryption
# 2a864886f70d010301 1  DhKeyAgreement
# 2a8648ce3e0201 1  DHPublicKey
def extract_keys(
    list_of_files: str,
    out_file: str = None,
    debug: bool = False,
    max_cnt: int = None,
    samples_file: str=None):
  samples = {}
  key_list = []
  f = open(list_of_files, 'r')
  files = f.read().split('\n')
  cnt = 0
  stats = collections.defaultdict(int)
  for fn in files:
    if max_cnt and stats['file_cnt'] >= max_cnt:
      break
    stats['file_cnt'] += 1
    try:
      with open(fn, 'r') as fp:
        txt = fp.read()
    except Exception:
      stats['invalid file'] += 1
      continue
    if isinstance(txt, bytes):
      try:
        txt = txt.decode("utf-8")
      except Exception:
        stats["not utf-8"] += 1
        continue
    try:
      for header, pem, asn in extract_pem(txt, debug, fn, stats):
        if isinstance(header, bytes):
          try:
            header = header.decode("utf-8")
          except Exception:
            stats["invalid utf-8"] += 1
            continue
        stats['asn_cnt'] += 1
        try:
          asn_struct = asn_parse.parse(asn, strict=False)
          stats["valid " + header ] += 1
          if header not in samples:
            samples[header] = pem
        except Exception as ex:
          headerex = "invalid " + header
          stats[headerex] += 1
          stats['parse_error'] += 1
          if headerex not in samples:
            samples[headerex] = pem
          if debug:
            print('*** cannot parse asn:' + str(ex))
            print('file:', fn)
            print('pem:', pem)
          continue
        for key in extract_keys_from_struct(asn_struct):
          stats['key_cnt'] += 1
          key["source"] = fn
          key_list.append(key)
    except Exception as ex:
      stats['skipped_files'] += 1
      if debug:
        print('*** Skipping file:', fn)
        print('    Reason:', str(ex))
  if out_file is not None:
    f = open(out_file, 'w')
    json.dump(key_list, f, indent=2)
    f.close()
    print("keys written to", out_file)
  print(f"len(key_list):{len(key_list)}")
  print_dict("Stats", stats)
  c = collections.Counter(key["algorithm"] for key in key_list)
  print_dict("Algorithms", c)
  if samples_file is not None:
    print_samples(samples_file, samples)


def extract_pems(
    list_of_files: str,
    expected_header: str,
    out_file: str = None,
    debug: bool = False,
    max_cnt: int = None):
  pem_list = []
  f = open(list_of_files, 'r')
  files = f.read().split('\n')
  cnt = 0
  stats = collections.defaultdict(int)
  for fn in files:
    if max_cnt and len(pem_list) >= max_cnt:
      break
    stats['file_cnt'] += 1
    try:
      with open(fn, 'r') as fp:
        txt = fp.read()
    except Exception:
      stats['invalid file'] += 1
      continue
    if isinstance(txt, bytes):
      try:
        txt = txt.decode("utf-8")
      except Exception:
        stats["not utf-8"] += 1
        continue
    try:
      for header, pem, asn in extract_pem(txt, debug, fn, stats):
        if isinstance(header, bytes):
          try:
            header = header.decode("utf-8")
          except Exception:
            stats["invalid utf-8"] += 1
            continue
        if header != expected_header:
          continue
        pem_list.append(pem)
    except Exception as ex:
      stats['skipped_files'] += 1
      if debug:
        print('*** Skipping file:', fn)
        print('    Reason:', str(ex))
  if out_file is not None:
    f = open(out_file, 'w')
    json.dump(pem_list, f, indent=2)
    f.close()
    print("pems written to", out_file)
  print(f"len(pem_list):{len(pem_list)}")
  print_dict("Stats", stats)

def extract_certs(
    list_of_files: str,
    out_file: str = None,
    debug: bool = False,
    max_cnt: int = None,
    samples_file:str = None):
  expected_header = "CERTIFICATE"
  pem_list = []
  samples = {}
  f = open(list_of_files, 'r')
  files = f.read().split('\n')
  cnt = 0
  stats = collections.defaultdict(int)
  for fn in files:
    if max_cnt and len(pem_list) >= max_cnt:
      break
    stats['file_cnt'] += 1
    try:
      with open(fn, 'r') as fp:
        txt = fp.read()
    except Exception:
      stats['invalid file'] += 1
      continue
    if isinstance(txt, bytes):
      try:
        txt = txt.decode("utf-8")
      except Exception:
        stats["not utf-8"] += 1
        continue
    try:
      for header, pem, asn in extract_pem(txt, debug, fn, stats):
        if isinstance(header, bytes):
          try:
            header = header.decode("utf-8")
          except Exception:
            stats["invalid utf-8"] += 1
            continue
        if header != expected_header:
          continue
        pem_list.append(pem)
        struct = asn1crypto.x509.Certificate.load(asn).native
        # print(struct)
        tbs_cert = struct['tbs_certificate']
        sig_alg = tbs_cert['signature']['algorithm']
        if sig_alg not in samples:
          samples[sig_alg] = pem
        stats[sig_alg] += 1
    except Exception as ex:
      stats['skipped_files'] += 1
      if debug:
        print('*** Skipping file:', fn)
        print('    Reason:', str(ex))
  if out_file is not None:
    f = open(out_file, 'w')
    json.dump(pem_list, f, indent=2)
    f.close()
    print("pems written to", out_file)
  print_samples(samples_file, samples)
  print(f"len(pem_list):{len(pem_list)}")
  print_dict("Stats", stats)

def test():
  extract_keys(f"{KEY_HUNT}/pem_files.txt",
               out_file = f"{KEY_HUNT}/test_keys.json",
               debug=True,
               max_cnt=500,
               samples_file = f"{SAMPLES}/pem_samples0.txt")

def all():
  extract_keys(f"{KEY_HUNT}/pem_files.txt",
               f"{KEY_HUNT}/extracted_keys.json",
               debug=False,
               max_cnt=None,
               samples_file = f"{SAMPLES}/pem_samples.txt")

def certs():
  extract_pems(f"{KEY_HUNT}/pem_files.txt",
               "CERTIFICATE",
               f"{KEY_HUNT}extracted_certs.json",
               debug=False,
               max_cnt=None)

def certs2():
  extract_certs(f"{KEY_HUNT}/pem_files.txt",
               f"{KEY_HUNT}extracted_certs2.json",
               debug=False,
               max_cnt=None,
               samples_file = f"{SAMPLES}/cert_samples.txt")
               
if __name__ == "__main__":
  certs2()

