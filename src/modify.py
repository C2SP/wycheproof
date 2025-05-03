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

class CaseCtr:

  def __init__(self, valid_arguments=None):
    self.current_case = 0
    self.case_cntr = 0
    self.val = None
    self.args = {}
    if valid_arguments is None:
      self.valid_arguments = []
    else:
      self.valid_arguments = valid_arguments

  def __call__(self, val):
    trigger = self.case_cntr == self.current_case
    if trigger:
      self.val = val
    self.case_cntr += 1
    return trigger

  def add(self, **args):
    self.args |= args

  def found(self):
    return self.case_cntr > self.current_case

  def next_case(self):
    self.current_case += 1
    self.case_cntr = 0
    self.val = None
    self.args = {}


def CaseIter(det_func, *args):
  '''Iterates over modification of a deterministic function.
     The first argument of det_func is an instance oftype CaseCtr. *args
     are additional arguments passed to det_func. det_func
     is called repeatedly. During the n-th pass the n-th call
     to CaseCtr returns true, the value passed to this call
     it returned together with the result of det_func.
  >>> def example(case, L):
  ...   R = L[:]
  ...   if len(R) >= 0 and case("case1"): R[0] = 5
  ...   if len(R) >= 1 and case("case2"): R[1] = 7
  ...   if case("case3"): R = []
  ...   return R
  ...
  >>> for L,c in CaseIter(example, [1, 2, 3]):
  ...   print("%s, %s"%(L,c))
  [5, 2, 3], case1
  [1, 7, 3], case2
  [], case3
  
  Args:
    def_func: a deterministic function
  Returns:
    an iterator 
  '''
  case = CaseCtr()
  while True:
    try:
      res = det_func(case, *args)
    except Exception as ex:
      print(f"Exception {ex} during case {case.val}")
      raise ex
    if case.found():
      yield res, case.val
      case.next_case()
    else:
      return


def CaseIterWithFlags(det_func, *args):
  """Like Case iter but allows to return flags.

  >>> def example(case, L):
  ...   R = L[:]
  ...   if len(R) >= 0 and case("case1"):
  ...      case.add(flags=["hello"])
  ...      R[0] = 5
  ...   if len(R) >= 1 and case("case2"): R[1] = 7
  ...   if case("case3"): R = []
  ...   return R
  ...
  >>> for L, c, flags in CaseIterWithFlags(example, [1, 2, 3]):
  ...   print("%s, %s, %s"%(L, c, flags))
  [5, 2, 3], case1, ["hello"]
  [1, 7, 3], case2, []
  [], case3, []

  Args:
    def_func: a deterministic function

  Returns:
    an iterator
  """
  case = CaseCtr(valid_arguments=["flags"])
  while True:
    try:
      res = det_func(case, *args)
    except Exception as ex:
      print(f"Exception {ex} during case {case.val}")
      raise ex
    if case.found():

      yield res, case.val, case.args.get("flags", [])
      case.next_case()
    else:
      return
