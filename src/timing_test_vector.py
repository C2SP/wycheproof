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

import test_vector
class TimingTestVector(test_vector.TestVector):
  """TimingVector is the base class for test vectors meant to be used
     for testing against timing attacks. The main difference to
     TestVector is that these vectors do not have a field "result"
     as only the side-channel information is important."""

  # Attributes that are included in the test cases
  test_attributes = []

  # Attributes that are included in the test group
  group_attributes = []

  status = "alpha"

  # Description of the members of the subclasses.
  schema = {
    "tcId" : {
        "type" : int,
        "short" : "Identifier of the test case",
        "desc" : """A unique identifier of the test case in a test file.
                    The identifiers are continuous integers. The identifiers
                    of test vectors change between versions of the test file.
                    Hence, the triple (filename, version, tcId) uniquely
                    identifies a test vector."""
    },
    "comment" : {
         "type" : str,
         "desc" : "A brief description of the test case"
    },
    "flags" : {
        "type" : list[str],
        "short" : "A list of flags",
        "desc" : """A list of flags for a test case.
                    Flags are described in the header of the test file."""
    }
  }

  def __init__(self, **kwargs):
    for n in kwargs:
      setattr(self, n, kwargs[n])

  @classmethod
  def fields(self) -> list[str]:
    """Returns the fields that are in the test case of a test vector.
       All test vectors have some fileds in common:
       tcId: an integer that is unique in the test file.
       comment: A short description of the test case.
       flags: A list of flags, where the flags are described in the field
       notes in the top level."""
    if hasattr(self, "test_attributes"):
      attributes = self.test_attributes
    else:
      attributes = list(self.schema.keys())
    return (["tcId", "comment"] + attributes + ["flags"])

  def __repr__(self) -> str:
    fields = self.fields() + self.group_attributes
    fields = [f for f in fields if hasattr(self, f)]
    arglist = ", ".join("%s=%s"%(x,repr(getattr(self,x))) for x in fields)
    return "%s(%s)"%(type(self).__name__, arglist)

  def testrep(self) -> str:
    """Representation of the test, without tcId and comment.
       This representation is used to detect duplicates and remove them"""
    fields = self.fields()
    arglist = ", ".join("%s=%s"%(x,repr(getattr(self,x))) for x in fields
        if hasattr(self, x) and x not in ("tcId", "comment", "flags"))
    return "%s(%s)"%(type(self).__name__, arglist)

