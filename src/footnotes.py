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

import typing
import util
import flag

class FootNotes:
  def __init__(self):
    self.references = dict()
    self.flags = dict()

  @util.type_check
  def format_txt(self, txt: str) -> str:
    """Formats the text of a footnote.

    The texts for a footnote are sometimes doc strings.
    This function removes newlines and additional spacing.

    Args:
      txt: the text to format
    Returns:
      the formatted text
    """
    lines = txt.split("\n")
    lines = [x.strip() for x in lines]
    return " ".join(lines)

  def add_flag(self, flag: flag.Flag) -> str:
    label = self.get_label(flag.label, flag.description)
    self.flags[label] = flag
    return label

  def add_flags(self, flag_list: list[flag.Flag]) -> list[str]:
    return [self.add_flag(flag) for flag in flag_list]

  # TODO: deprecate
  def ref(self, label: str, txt: str) -> str:
    txt = self.format_txt(txt)
    f = flag.Flag(label, txt)
    return self.add_flag(f)

  def get_label(self, label: str, txt: str) -> str:
    """Returns a unique label for a given text.

    Args:
      label: the default value for the label. If this
        value is already used for another label then an unused
        value label_<int> is returned instead.
      txt: the description of the label.
    Returns:
      the name of the label.
    """
    cnt = 0
    while True:
      if cnt == 0:
        newlabel = label
      else:
        newlabel = f"{label}_{cnt}"
      cnt += 1
      if newlabel in self.references:
        if self.references[newlabel] == txt:
          return newlabel
      else:
        self.references[newlabel] = txt
        return newlabel

  def bug(self, bug_id: str, txt: typing.Optional[str] = None) -> str:
    """Defines a buganizer entry.

    Since buganizer is typically not accessible outside, these
    test vectors should not be released.

    Args:
      bug_id: a buganizer reference. Must start with "b/".
      text: optional text describing the bug.
    Returns:
      the label for the bug.
    """
    if bug_id[:2] != "b/":
      raise ValueError("bug_id must start with 'b/'")
    return self.ref(bug_id, txt)

  def ref_list(self, flags: typing.Set[str]) -> dict[str, flag.Flag]:
    return {f: self.flags[f] for f in sorted(flags)}

