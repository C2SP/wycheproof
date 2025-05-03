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

import json
import base64

TVDIR = "/google/src/cloud/bleichen/keymaster1/google3/third_party/wycheproof/testvectors/"

def get_enc(t):
  jwe = t["jwe"]
  if isinstance(jwe, str):
    header = pp(jwe)[0]
    try:
      header = eval(header)
      return header["enc"]    
    except Exception as ex:
      pass
  return None

def groups(x):
  yield from x["testGroups"]

def tv(x):
  for g in groups(x):
    for t in g["tests"]:
      yield g,t

def sort_keys(t, keys):
  tmp = {}
  for k in keys:
    if k in t:
      tmp[k] = t[k]
      del t[k]
  for k in tmp:
    t[k] = tmp[k]

def reformat(x):
  cnt = 0
  for g, t in tv(x):
    cnt += 1
    t["tcId"] = cnt
    enc = get_enc(t)
    if "enc" not in t:
      t["enc"] = enc
    else:
     assert enc == t["enc"]  
    sort_keys(t, ["enc", "jwe", "result", "flags"])

def dec(s):
  return base64.urlsafe_b64decode(s + "="*(-len(s)%4))

def pp(s):
  return [dec(x) for x in s.split(".")]

def b64toint(s):
  return int.from_bytes(dec(s), 'big')

def test(x):
  for g,t in tv(x):
    try:
      print(t["tcId"], t["comment"])
      jwe = t["jwe"]
      if "private" in g:
        print("  ", g["private"]["alg"])
      if isinstance(jwe, str):
        for s in pp(jwe):
          print("  ", s)
    except Exception as e:
      print("   *****", e)

def test2(x):
  for g,t in tv(x):
    print(t["tcId"], t["comment"])
    try:
      jws = t["jws"]
      if "private" in g:
        p = g["private"]
        if "alg" in p:
          print("  ", p["alg"])
        else: 
          print("  ", p)
      if isinstance(jws, str):
        for s in pp(jws):
          print("  ", s)
    except Exception as e:
      print("   *****", e)

def dump(t, morelines, prefix="    ", pos=3):
  td = json.dumps(t, indent=2).split("\n")
  for l in td[:pos] + morelines + td[pos:]:
    print(prefix + l)


def contalg(x, short: bool):
  g0, e0 = None, None
  for g,t in tv(x):
    jwe = t["jwe"]
    if isinstance(jwe, str):
      enc = None
      header = pp(jwe)[0]
      try:
        header = eval(header)
        enc = header["enc"]    
      except Exception as ex:
        pass
      if short:
        print(t["tcId"], header)
      else:
        if g != g0 or enc != e0:
          g0 = g
          e0 = enc        
          morelines = [
            f'  "enc" : "{enc}",',
          ]
          dump(g, morelines, "  ")
        dump(t,[])


def enc(s):
  w = base64.urlsafe_b64encode(s)
  w = w.replace(b"=",b"")
  return w.decode("utf-8")


def trunc_tag(jwe, cnt):
  L = pp(jwe)
  L[-1] = L[-1][:-cnt]
  return ".".join(enc(s) for s in L)

def check_duplicate(x):
  seen = set()
  for g in groups(x):
    p = str(g['private'])
    if p in seen:
      print('duplicate', p)
    seen.add(p)

def get_test_vectors(filename):
  with open(TVDIR + filename) as f:
    return json.load(f)


def t0():
  test(get_test_vectors("json_web_encryption_test.json"))

def tcalg():
  x = get_test_vectors("json_web_encryption_test.json")
  contalg(x, True)
  contalg(x, False)

def reformat_jwe():
  x = get_test_vectors("json_web_encryption_test.json")
  check_duplicate(x)
  reformat(x)
  for g in groups(x):
    gs = json.dumps(g, indent=2) + ","
    for l in gs.split("\n"):
      print("    " + l)
  
def t2():
  x = get_test_vectors("json_web_signature_test.json")
  test2(x)


if __name__ == "__main__":
  # t2()
  t0()
  # reformat_jwe()
