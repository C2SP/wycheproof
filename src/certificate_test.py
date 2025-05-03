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

import certificate
import pem_samples
import json
import collections
import ec_groups

def test_pems(certificates, algorithms=None,*,
              log=False):
  print('-----TEST PEMS -------')
  for txt, pem in certificates:
    try:
      cert = certificate.from_pem(pem)
      # certificate.pprint(cert)
      alg = cert.get_algorithm()
      if algorithms is None or alg not in algorithms:
        if log: print(f'skipping {alg}')
        continue
      if log: print(f"----- {alg} -----")
      if alg == 'rsa':
        cert.analyze_rsa()
      elif alg == 'ec':
        if log:
          print(str(cert))
        cert.analyze_ec()
      else:
        print('not yet analyzed:', alg)
    except Exception as ex:
      print(ex)
      continue

def test_ecdsa_signatures(certs, min_cnt=2, outfile=None):
  print(len(certs))
  pubkeys = collections.defaultdict(list)
  rs = collections.defaultdict(list)
  for pem in certs:
    try:
      cert = certificate.from_pem(pem)
      # certificate.pprint(cert)
      alg = cert.get_algorithm()
      if alg != "ec":
        continue
      sig = cert.ecdsa_signature()
      for pub in cert.ec_public_keys():
        pubkeys[pub].append(sig)
      r,s = sig
      rs[r].append(s)
    except Exception as ex:
      # print(ex)
      continue
  res = {}
  for pub, sigs in pubkeys.items():
    if len(set(sigs)) >= min_cnt:
      res[pub.hex()] = list(set(sigs))
      print(pub.hex(), len(sigs), len(set(sigs)))
  if outfile is not None:
    f = open(outfile, 'w')
    json.dump(res, f, indent=2)
    f.close()
    print("signatures written to", outfile)

  for r, ss in rs.items():
    if len(set(ss)) > 1:
      print('duplicate r', r, ss)

def extract_ecdsa_signatures(certs, min_cnt=2, outfile=None):
  print('number of certificates with ECDSA signatures:', len(certs))
  pubkeys = collections.defaultdict(list)
  for pem in certs:
    try:
      cert = certificate.from_pem(pem)
      # certificate.pprint(cert)
      alg = cert.get_algorithm()
      if alg != "ec":
        continue
      for pub, info in cert.ec_public_keys_extended():
        pubkeys[pub].append(info)
    except Exception as ex:
      # print(ex)
      continue
  res = []
  for pub, sig_infos in pubkeys.items():
    # Count the number of unique signatures.
    sigs = []
    groups = set()
    mds = set()
    infos = []
    for info in sig_infos:
      sig = (info['r'], info['s'], info['digest'], info['md'])
      groups.add(info['curve'])
      if sig not in sigs:
        sigs.append(sig)
    assert len(groups) == 1
    if len(sigs) >= min_cnt:
      group = list(groups)[0]
      curve = ec_groups.named_curve(group)
      signatures = [
        {'r': r,
         's': s,
         'md': md,
         'digest': digest}
         for r, s, digest, md in sigs]
      res.append({
         'curve': group,
         # for convenience
         'n' : curve.n,
         'pub': pub.hex(),
         'signatures': signatures})
      print(pub.hex(), len(sigs), len(sig_infos))
  if outfile is not None:
    f = open(outfile, 'w')
    json.dump(res, f, indent=2)
    f.close()
    print("signatures written to", outfile)  

def all_tests():
  test_pems(pem_samples.CERTIFICATE_SAMPLES, log=True)

def test_certs2():
  filename = "extracted_certs2.json"
  outfile="ecdsa_signatures.json"
  f = open(filename)
  certs = json.load(f)
  extract_ecdsa_signatures(certs, outfile=outfile)
  
if __name__ == '__main__':
  test_certs2()
