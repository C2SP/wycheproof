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
import io
import json
import pathlib
import sys
import test_vector
import typing
import reflection

def get_test_types():
  return reflection.all_subclasses([test_vector.TestType])

def get_test_groups():
  res = {}
  for mod in reflection.all_modules():
    if getattr(mod, "STATUS", "") == "alpha":
      continue
    for n in dir(mod):
      obj = getattr(mod, n)
      if isinstance(obj, type):
        if issubclass(obj, test_vector.TestGroup):
          if obj.testtype is None:
            continue
          t = obj.testtype.__name__
          v = obj.vectortype.__name__
          if t in res:
            raise ValueError("name collision for %s in %s: %s" % (t, n, v))
          res[t] = (n,v)
  # We might sort the classes differently at some time.
  # For now this uses alphabetic order.
  return collections.OrderedDict((n, res[n]) for n in sorted(res))


def special(test, compact: bool = True, verbose: bool = True):
  """Currently the following counts are reported:

     (1) number of valid vectors (typically declines when something is wrong)
     (2) number of acceptable vectors with no flags (this is now an error)

     Args:
       test: the content of a JSON file with test vectors
       compact: Determines if the results are returned in a compact format.
         Typically, tables in documents are compact, while output for a JSON
         file are not compact.
       verbose: Include verbose information (i.e. missing flags)
  """
  missing_flags = collections.defaultdict(int)
  other = collections.defaultdict(int)
  no_flags = 0
  valid = 0
  acceptable = 0
  invalid = 0
  for g in test["testGroups"]:
    for t in g["tests"]:
      if "result" in t:
        if t["result"] == "valid":
          valid += 1
        elif t["result"] == "acceptable":
          acceptable += 1
        elif t["result"] == "invalid":
          invalid += 1
        else:
          other[t["result"]] += 1
        if "flags" not in t or not t["flags"]:
          missing_flags[t["result"]] += 1
  if compact:
    yield "validity", (valid, acceptable, invalid)
    # yield "validity", "%d, %d, %d" % (valid, acceptable, invalid)
  else:
    yield "validTestVectors", valid
    yield "acceptableTestVectors", acceptable
    yield "invalidTestVectors", invalid
  if verbose and sum(missing_flags.values()) > 0:
    yield "missingFlags", tuple(
        missing_flags[x] for x in ("valid", "acceptable", "invalid"))
    for key, val in other.items():
      yield key, val


def get_file_stats(compact: bool, test_vector_path: str, verbose: bool = True):
  res = {}
  src_path = pathlib.Path(test_vector_path)
  for path in src_path.glob("*.json"):
    name = str(path).split("/")[-1]
    f = path.open()
    try:
      stats = collections.OrderedDict()
      res[name] = stats
      tv = json.load(f)
      stats["algorithm"] = tv["algorithm"]
      testgroups = tv["testGroups"]
      test_types = set(t["type"] for t in testgroups)
      assert len(test_types) == 1
      stats["testType"] = list(test_types)[0]
      stats["schema"] = tv["schema"]
      stats["tests"] = tv["numberOfTests"]
      stats["groups"] = len(testgroups)
      if not compact:
        stats["generatorVersion"] = tv["generatorVersion"]
    except Exception as ex:
      stats["exception"] = str(ex)
      print(name, str(ex))
    for n, val in special(tv, compact, verbose):
      stats[n] = val
  sorted_res = collections.OrderedDict()
  for n in sorted(res):
    sorted_res[n] = res[n]
  return sorted_res

def printstats(formatter: doc.Formatter,
               compact: bool,
               test_vector_path: str,
               verbose: bool = True):
  stats = get_file_stats(compact, test_vector_path, verbose)
  ftypes = collections.defaultdict(list)
  schema = collections.defaultdict(list)
  for n in stats:
    t = stats[n]
    assert "testType" in t, n
    tt = t["testType"]
    ftypes[tt].append(n)
    if t["schema"] not in schema[tt]:
      schema[tt].append(t["schema"])

  test_types = get_test_types()
  test_groups = get_test_groups()

  formatter.format_file_header()
  formatter.format_heading("Test vector files", level=1)

  # Files in alpha status
  alpha = []

  for name in sorted(ftypes):
    if name not in test_types:
      alpha.append(name)
      continue

    formatter.format_heading(name, level=2, anchor=name)
    if name in test_types:
      t = test_types[name]
      formatter.format_doc_str(t.__doc__)
      formatter.line()
    if name in schema:
      # Expect one to one relations:
      test_group, test_vector = test_groups[name]
      # Can't reference files outside g3doc
      # schemas = [formatter.file_ref(f, "../schemas/" + f)
      #                for f in schema[name]]
      schemas = schema[name]
      formatter.format("JSON schema: " + ", ".join(schemas))
      formatter.line()
      group_ref = formatter.inline_ref(test_group, local_file = "types")
      formatter.format("Type of the test group: " + group_ref)
      formatter.line()
      vector_ref = formatter.inline_ref(test_vector, local_file = "types")
      formatter.format("Type of the test vectors: " + vector_ref)
      formatter.line()
    tab = collections.OrderedDict()
    for fname in sorted(ftypes[name]):
      tab[fname] = stats[fname]
    formatter.format_dict(tab,
                          cols=["tests", "validity", "algorithm"],
                          skip=["groups", "testType", "schema"],
                          sortable=True)

  formatter.format_heading("Total number of test vectors", level=2)
  total = {
      # "algorithm": collections.Counter(),
      "tests": 0,
      "validity": [0, 0, 0],
      "missingFlags": [0, 0, 0],
  }

  for name, t in stats.items():
    if t["testType"] in alpha:
      continue
    for n in total:
      if n in t:
        if isinstance(total[n], list):
          size = min(len(t[n]), len(total[n]))
          for j in range(size):
            try:
              total[n][j] += int(t[n][j])
            except:
              formatter.format(
                  f"not an integer: {name}, {n}, {j} {type(t[n])} {t[n]}")
        elif isinstance(total[n], dict):
          total[n][t[n]] += 1
        else:
          total[n] += t[n]
  for n, val in total.items():
    formatter.format(f"{n}: {val}")

  if len(alpha) > 0:
    formatter.format_heading("Incomplete tests", level=2)
    formatter.format(", ".join(alpha))
  formatter.format_file_end()


def gen_g3doc(f: io.IOBase, test_vector_path: str, verbose: bool = True):
  printstats(
      doc.G3doc(f),
      compact=True,
      test_vector_path=test_vector_path,
      verbose=verbose)


def gen_html(f: io.IOBase, test_vector_path: str, verbose: bool = True):
  printstats(
      doc.Html(f),
      compact=True,
      test_vector_path=test_vector_path,
      verbose=verbose)


def gen_json(f: io.IOBase, test_vector_path: str, verbose: bool = True):
  res = get_file_stats(
      compact=False, test_vector_path=test_vector_path, verbose=verbose)
  json.dump(res, f, indent=2)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--format",
                      type=str,
                      choices=["g3doc", "html", "json"],
                      default="g3doc")
  parser.add_argument(
      "--out",
      type=str,
      help="Output file name",
      default="")
  parser.add_argument(
      "--testvector_path",
      type=str,
      help="path for test vector files",
      default="../testvectors/")
  namespace = parser.parse_args()
  if namespace.out:
    f = open(namespace.out, "w")
  else:
    f = sys.stdout
  path = namespace.testvector_path
  if namespace.format == "g3doc":
    gen_g3doc(f, path)
  elif namespace.format == "html":
    gen_html(f, path)
  elif namespace.format == "json":
    gen_json(f, path)
  else:
    raise ValueError("Unknown format:" + namespace.format)
