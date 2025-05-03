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
import tarfile
import json
import io


def add_fields(tar, test, name_prefix: str, field: str, filter_func=None):

  def add_file(name: str, content):
    if isinstance(content, str):
      content = content.encode('ascii')
    if tar is None:
      return
    s = io.BytesIO(content)
    tarinfo = tarfile.TarInfo(name)
    tarinfo.size = len(content)
    tar.addfile(tarinfo, s)

  if name_prefix is None:
    name_prefix = field
  for test_group in test['testGroups']:
    for tv in test_group['tests']:
      if filter_func and not filter_func(tv):
        continue
      filename = name_prefix + str(tv['tcId'])
      content = tv[field]
      add_file(filename, content)


Parser = argparse.ArgumentParser


def get_parser() -> Parser:
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--inp', type=str, help='the filename of a JSON file with test vectors.')
  parser.add_argument(
      '--out',
      type=str,
      help='the filename of the tar file to generate',
      default='')
  parser.add_argument('--field', type=str, help='the field to select')
  parser.add_argument(
      '--filename_prefix',
      type=str,
      help='the prefix for the names of the files in the tar file.')

  return parser

def json_to_tar(
    input_file: str,
    output_file: str,
    filename_prefix: str,
    field: str):
  tar = tarfile.open(output_file, 'w')
  test = json.load(open(input_file))
  add_fields(tar, test, filename_prefix, field)
  tar.close()

def main(namespace):
  json_to_tar(namespece.inp, namespace.out, namespace.filename_prefix,
              namespace.field)

if __name__ == '__main__':
  parser = get_parser()
  namespace = parser.parse_args()
  main(namespace)
