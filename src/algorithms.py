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

from typing import Optional, List

# TODO: Replace oid_table with this module.
# TODO: Replace test_vector.Algorithm with this module.

ALGORITHMS = {}
TYPES = {}

class Algorithm:
  def __init__(
      self,
      name: str,
      oid: Optional[str],
      ref: Optional[str],
      doc: Optional[str],
      alg_type: Optional[str]) :
    """Defines an algorithm.

    Args:
      name:
           the name of the algorithm
      oid_nodes:
           the oid of the algorithm in node format e.g. "2.16.840.1.101.3.4.2.1"
      ref: 
           a reference for the definition of the OID (e.g. "RFC xxx")
      doc:
           Wychproof documentation (e.g. "ECDSA.md")
      alg_type:
          algorithm type (e.g. "HashFunction")
    """
    self.name = name
    self.oid_nodes = oid_nodes
    self.ref = ref
    self.doc = doc
    self.types = types

      

