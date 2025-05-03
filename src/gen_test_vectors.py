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

import argparse
import collections
import doc
import json
import multiprocessing
import os
import pathlib
import test_vector
import time
import typing
import util
import tarfile
import traceback
import cProfile

# Currently python3.8 or higher is required.
util.check_python_version()


class Namespace:
  pass

def release_dir() -> str:
  current_dir = os.getcwd()
  pattern = ""
  pos = current_dir.find(pattern)
  assert pos >= 0
  newpath = os.path.join(current_dir[:pos],
      "third_party/wycheproof/testvectors/")
  return newpath

def internal_dir() -> str:
  return "../testvectors/"

def tar_dir() -> str:
  return "../tar"

def generate_test_vector_file(age: int, fname: str, out: str, desc: dict, log: bool):
  name = desc['generator']
  assert name[-3:] == '.py'
  name = name[:-3]
  namespace = Namespace()
  namespace.out = out
  for k, v in desc.items():
    if k not in ('generator', 'status', 'subdir'):
      setattr(namespace, k, v)
  try:
    mod = __import__(name)
    if log:
      print('generating', fname)
    start = time.time()
    mod.main(namespace)
    if log:
      print('generated', fname, time.time() - start)
  except Exception:
    print('Error while generating', fname)
    traceback.print_exc()


def generate_tar(filenames, tarname:str, log: bool):
  if not tarname:
    tarname = f"testvectors_{test_vector.GENERATOR_VERSION}.tar.gz"
  tarfilename = name=os.path.join(tar_dir(), tarname)
  tar = tarfile.open(tarfilename, 'w:gz')
  cnt = 0
  for fn in filenames:
    tar.add(fn)
    cnt += 1
  tar.close()
  if log:
    print(f'{cnt} test vector files written to {tarfilename}')

def gen_test_vectors(namespace,
        test_vector_files=None):
  log = not namespace.silent
  if log:
    print("Generating with arguments:")
    for arg in dir(namespace):
      if arg[0] == '_':
        continue
      print(arg, ':', getattr(namespace, arg))
  # Reads the descriptions of the test vector files.
  if test_vector_files is None:
    test_vector_files = json.load(open(namespace.files))
  # Determines, which files are selected.
  if namespace.version == 'release':
    selection = ['release']
  elif namespace.version == 'internal':
    selection = ['release', 'internal']
  elif namespace.version == 'alpha':
    selection = ['release', 'internal', 'alpha']
  else:
    raise ValueError('Unknown version:' + namespace.version)
  if getattr(namespace, "dir", None):
    testvector_dir = namespace.dir
  elif namespace.version == "release":
    testvector_dir = release_dir()
  else:
    testvector_dir = internal_dir()
  if log:
    print("Output directory:", testvector_dir)
  # Selects the files, that are generated
  files = []
  contains = getattr(namespace, 'contains', '')
  if contains is None:
    parts = []
  else:
    parts = contains.split(',')
  generator_prefix = getattr(namespace, 'gen', '')
  max_age = getattr(namespace, 'age', 0)
  filenames = []
  for filename, desc in test_vector_files.items():
    if not desc["generator"].startswith(generator_prefix):
      continue
    if desc["status"] not in selection:
      continue
    if not all(subs in filename for subs in parts):
      continue

    if 'subdir' in desc:
      subdir = desc['subdir']
    else:
      subdir = ''
    out = os.path.join(testvector_dir, subdir, filename)
    filenames.append(out)
    if os.path.exists(out):
      writeable = os.access(out, os.W_OK)
      age = int(time.time() - os.path.getctime(out))
    else:
      writeable = True
      age = 10**7
    if max_age and age < max_age:
      print("keeping:", filename)
      continue
    if not writeable:
      print('not writeable:', filename)
      continue
    files.append((age, filename, out, desc, log))

  files = sorted(files)[::-1]
  # Generates the files.
  start = time.time()
  if getattr(namespace, "prof", False):
    with cProfile.Profile() as pr:
      for args in files:
        generate_test_vector_file(*args)
      pr.print_stats(sort=1)
  elif getattr(namespace, 'poolsize', 1) > 1:
    with multiprocessing.Pool(namespace.poolsize) as p:
      p.starmap(generate_test_vector_file, files)
  else:
    for args in files:
      generate_test_vector_file(*args)

  # Make a tar file if requested
  tar_name = getattr(namespace, 'tar_name', '')
  make_tar = getattr(namespace, 'make_tar', False)
  if make_tar or tar_name:
    generate_tar(filenames, tar_name, log)
  print('total time used:', time.time()-start)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--version',
                      type=str,
                      choices=["release", "internal", "alpha"],
                      help='the version of the test vectors to generate',
                      default='alpha')
  parser.add_argument('--age',
                      type=int,
                      help='keep existing files if not older than this many seconds',
                      default=10800)
  parser.add_argument('--dir',
                      type=str,
                      help='The directory for the test vectors.')
  parser.add_argument('--poolsize',
                      type=int,
                      help='The pool size for multiprocessing',
                      default=12)
  # TODO: nargs='+' does not seem to work for strings.
  parser.add_argument('--contains',
                      type=str,
                      help='generate only files that contain all the substrings. '
                           'E.g. --contains=ecdsa,sha256 generates ECDSA signature '
                           ' using SHA-256.')
  parser.add_argument('--gen',
                      type=str,
                      help='generates only files that use a generator with the '
                           'given prefix (E.g. --gen gen_ec generates ECDH and '
                           'ECDSA files)',
                      default='')
  parser.add_argument('--files',
                      type=str,
                      default='gen_files.json',
                      help='list of files to generate')
  parser.add_argument('--silent',
                      action='store_true',
                      help='suppresses logging')
  parser.add_argument('--tar_name',
                      type=str,
                      help='name for tar file ')
  parser.add_argument('--make_tar',
                      action='store_true',
                      help='makes a tar file with name testvectors_version.tar '
                           'if tar_name is not specified.')
  parser.add_argument("--prof",
                      action='store_true',
                      help='makes a CPU profile. Uses poolsize=1.')

  namespace = parser.parse_args()
  gen_test_vectors(namespace)

if __name__ == "__main__":
  main()
