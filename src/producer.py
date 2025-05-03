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
import formatter
import test_vector

Parser = argparse.ArgumentParser


class Producer:
  """Produces a file with test vectors.

  A task of the producer is responsible for handling command line arguments,
  with the goal that test vectors can be generated either from python
  (i.e. by calling produce(), or from a commandline i.e. by calling
  produce_with_args()).
  The actual test vector generation is handled by subclasses of
  testvector.Generator.
  """

  def generate_test_vectors(self, namespace):
    raise ValueError('Must be implemented by subclass')

  def default_parser(self) -> Parser:
    parser = argparse.ArgumentParser()
    # Test vectors with buganizer entires are not meant for release.
    parser.add_argument(
        '--alpha',
        help='include test vectors that are experimental or buganizer entries',
        action='store_true')
    parser.add_argument(
        '--internal',
        help='generates internal version of the test vectors',
        action='store_true')
    parser.add_argument(
        '--release',
        help='generates release version of the test vectors',
        action='store_true')
    parser.add_argument(
        '--deprecated',
        help='used to add a deprecation message to a file',
        type=str,
        default='')
    parser.add_argument(
        '--header',
        type=str,
        nargs='*',
        help='additional comments added to the header of the test vectors')
    parser.add_argument(
        '--out',
        type=str,
        help='the output file for the test vectors',
        default='')
    return parser

  def parser(self) -> Parser:
    """Returns a parser for command line arguments.

    Returns:
      A parser for command line arguments.
      The parser returned by this function should be a extension of
      get_default_parser(). If a test vector generation does not use any
      additional arguments then it is possible to define this in the subclass
      of Producer by
        parser = lambda self: self.default_parser()
    """
    raise ValueError('Must be implemented by subclass')

  def get_formatter(self, namespace):
    return formatter.JsonFormatter(namespace.out)

  def produce(self, namespace):
    """Generates test vectors specified by parameters in a namespace.

    Args:
      namespace: an instance of arg_parse.namespace or an object with similar
        fields. The fields of the namespace are defined by the parser returned
        by parser().
    """
    test_vectors = self.generate_test_vectors(namespace)
    if not isinstance(test_vectors, test_vector.Test):
      raise ValueError(f"Expecting test_vector.Test got {type(test_vectors)}")
    formatter = self.get_formatter(namespace)
    test_vectors.format_all_vectors(formatter)

  def produce_with_args(self):
    """Produces test vectors using command line arguments.

    The command line arguments are described by the parser returned from
    the function parser().
    """
    namespace = self.parser().parse_args()
    self.produce(namespace)
