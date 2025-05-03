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

# Just some code for generating some documentation.
import collections
import html
import io
import util
import sys
from typing import Any, Optional, Union


class Table:
  def __init__(self, items):
    self.items = items
    self.rows = len(items)
    if self.rows == 0:
      self.columns = 0
    else:
      self.columns = len(items[0])
    for L in items:
      assert len(L) == self.columns

# ------ Type hints ------
Text = Union[str, list[str], Table]
Formatted = str  # formatted text

class Formatter:
  pass

class G3doc(Formatter):
  # TODO: Remove old_style if the new formatting
  #   of links works. Also update the real texts, bibliography etc.
  @util.type_check
  def __init__(self, f: Optional[io.IOBase] = None, old_style: bool = False):
    """ Constructs a formatter

    Args:
      f: the output
      old_style: uses explicit links for headers. This only works for g3doc, but
        not for github.
    """
    if f is None:
      self.f = sys.stdout
    else:
      self.f = f
    self.old_style = old_style

  # ----- String formatting -----

  def format_anchor(self, anchor: str):
    if self.old_style:
      return anchor
    else:
      anchor = anchor.lower()
      anchor = anchor.replace(" ", "-")
      return anchor

  def inline_ref(self,
                 text,
                 anchor: Optional[str] = None,
                 local_file: str = ""):
    if anchor is None:
      anchor = text
    anchor = self.format_anchor(anchor)
    if local_file:
      local_file += ".md"
    return f"[{self.escape(text)}]({local_file}#{anchor})"

  def file_ref(self,
               text: str,
               path: str):
    return f"[{self.escape(text)}]({path})"

  def escape(self, s):
    if not isinstance(s, str):
      if isinstance(s, type):
        s = s.__name__
      else:
        s = str(s)
    s = s.replace("|", "\|")
    s = s.replace(":", "\:")
    s = s.replace("\n", " ")
    return s

  def bold(self, s: str) -> str:
    return "**" + s + "**"

  def colname(self, s: str) -> str:
    return self.bold(self.escape(s))

  # ----- Output methods -----

  @util.type_check
  def line(self, line: str = ""):
    if isinstance(line, str):
      self.f.write(line)
      self.f.write("\n")

  def lines(self, *lines):
    if lines:
      for l in lines:
        self.line(l)

  def format_file_header(self):
    self.format_comment("AUTO-GENERATED FILE; DO NOT MODIFY")

  def format_file_end(self):
    pass

  def format_comment(self, s: str):
    self.line(f"<!-- {s} -->")

  # TODO: Needs fixing: anchors only work if they
  #   are the same as section headers.
  def format_heading(self, s, level:int, anchor=None):
    assert level in (1,2,3,4,5,6)
    txt = "#" * level + " " + self.escape(s)
    if anchor and self.old_style:
      txt +=  "{#%s}" % anchor
    self.line(txt)

  def format_table_of_contents(self):
    self.lines("", "[TOC]")

  def format_table(self, t:Table):
    if t.rows:
      self.line(" | ".join(self.colname(x) for x in t.items[0]))
      self.line(" | ".join("---" for _ in range(t.columns)))
    for i in range(1, t.rows):
      self.line(" | ".join(self.escape(x) for x in t.items[i]))

  @util.type_check
  def format_dict(self,
                  d: dict,
                  first: str = "name",
                  cols: Optional[list[str]] = None,
                  skip: Optional[list[str]] = None,
                  sortable: bool = False,
                  format_func=None):
    if cols is None:
      cols = []
    if skip is None:
      skip = []
    for n,v in d.items():
      if not isinstance(v, dict):
        raise ValueError("Expecting dict for {n} got {v}")
      for m,_ in v.items():
        if m not in cols and m not in skip:
          cols = cols + [m]
    header = " | ".join(self.colname(x) for x in [first] + cols)
    if sortable:
      header += "| {.sortable}"
    self.line(header)
    self.line(" | ".join("---" for _ in range(len(cols) + 1)))
    for n,v in d.items():
      C = [""] * (len(cols) + 1)
      C[0] = n
      for i,m in enumerate(cols):
        if m in v:
          if format_func:
            C[i+1] = format_func(m, v[m])
          else:
            C[i+1] = v[m]
      self.line(" | ".join(self.escape(x) for x in C))

  def format_doc_str(self, txt: str) -> None:
    self.format([line.strip() for line in txt.split("\n")])

  def format(self, txt: Text, escape: bool = True) -> None:
    if isinstance(txt, str):
      if escape:
        self.line(self.escape(txt))
      else:
        self.line(txt)
    elif isinstance(txt, list):
      for x in txt:
        self.format(x, escape)
    elif isinstance(txt, Table):
      self.format_table(txt)

class Html(Formatter):
  def __init__(self, f=None):
    if f is None:
      self.f = sys.stdout
    else:
      self.f = f

  def inline_ref(self, text: str, anchor: Optional[str] = None, local_file=""):
    if anchor is None:
      anchor = text
    anchor = self.format_anchor(anchor)
    if local_file:
      local_file += ".html"
    return f'<a href="{local_file}#{anchor}">{self.escape(text)}</a>'


  def file_ref(self, text, path):
    return f'<a href="{path}">{text}</a>'

  @util.type_check
  def line(self, line: str = ""):
    self.f.write(line)
    self.f.write("\n")

  def lines(self, *lines):
    if lines:
      for l in lines:
        self.line(l)

  def escape(self, s: Any) -> str:
    if not isinstance(s, str):
      if isinstance(s, type):
        s = s.__name__
      else:
        s = str(s)
    return html.escape(s)

  def bold(self, s):
    return "<b>" + s + "</b>"

  def tableheader(self, s, tab=4):
    return " " * tab + "<th>" + self.escape(s) + "</th>"

  def tableentry(self, s, tab=4):
    return " " * tab + "<td>" + self.escape(s) + "</td>"

  def format_file_header(self):
    header = """
<!-- AUTO-GENERATED FILE; DO NOT MODIFY -->
<head>
  <style>
  table, th, td {
    border: 1px solid black;
    border-collapse: collapse;
  }
  th, td {
    padding: 4px;
  }
  th {
    text-align: left;
  }
  </style>
</head>"""
    self.format(["<html>", header.split("\n"), "<body>"], escape=False)

  def format_file_end(self):
    self.lines("</body>", "</html>")

  def format_anchor(self, anchor: str):
    anchor = anchor.lower()
    anchor = anchor.replace(" ", "-")
    return anchor

  @util.type_check
  def format_heading(self, s: str, level: int, anchor=None):
    assert level in (1,2,3,4,5,6)
    if anchor:
      anchor = self.format_anchor(anchor)
      self.line(f'<h{level} id="{anchor}">{self.escape(s)}</h{level}>')
    else:
      self.line(f"<h{level}>{self.escape(s)}</h{level}>")

  @util.type_check
  def format_comment(self, s: str):
    self.line("<!-- %s -->" % s)

  def format_table_of_contents(self):
    pass

  def format_table(self, t:Table):
    self.line("<table>")
    if t.rows:
      self.line("  <tr>")
      for x in t.items[0]:
        self.line(self.tableheader(x))
      self.line("  </tr>")
    for i in range(1, t.rows):
      self.line("  <tr>")
      for x in t.items[i]:
        self.line(self.tableentry(x))
      self.line("  </tr>")
    self.line("</table>")

  def format_dict(self,
                  d: dict[str, dict[str, Any]],
                  first: str = "name",
                  cols: list[str] = [],
                  skip: list[str] = [],
                  sortable: bool = False,
                  format_func=None):
    """Formats a table given as a dict of dict.

    E.g. d = {
      "row0" : {
         "col_b" : 1,
         "col_c" : 2
      }
      "row1" : {
         "col_a" : 3,
         "col_b" : 4
       }
       "row2 : {
         "col_a" : 5,
         "col_c" : 6
       }

    format_dict(d, "row_name", ["col_a", "col_b") generates

     name   |  col_a  |  col_b  |  col_c
     ------------------------------------
     row0   |         |  1      |  2
     row1   |  2      |  3      |
     row2   |  5      |         |  6

    Args:
      d: the table as dict of dict
      first: the name of the first column (the indices of d)
      cols: a list of columns (this is just for ordering the columns)
      skip: columns that will be skipped
      sortable: if True make the table sortable (currently ignored)
      format_func: a function for formatting the cells
    """
    if not isinstance(d, dict):
      raise ValueError(f"Expecting dictionary, got {repr(d)}")
    for n,v in d.items():
      if not isinstance(v, dict):
        raise ValueError(f"Expecting dictionary for {n} got {d}")
      for m,_ in v.items():
        if m not in cols and m not in skip:
          cols = cols + [m]

    self.lines("<table>", "  <tr>")
    for n in [first] + cols:
      self.line(self.tableheader(n))
    self.line("  </tr>")
    for n,v in d.items():
      self.lines("  <tr>", self.tableentry(n))
      for m in cols:
        if m in v:
          val = v[m]
          if format_func is not None:
            val = format_func(m, val)
          self.line(self.tableentry(val))
        else:
          self.line(self.tableentry(""))
      self.line("  </tr>")
    self.line("</table>")

  def format_doc_str(self, txt: str):
    self.format(txt.split("\n"))

  def format(self, txt: Text, escape: bool = True) -> str:
    if isinstance(txt, str):
      if escape:
        self.line(self.escape(txt))
      else:
        self.line(txt)
    elif isinstance(txt, list):
      for x in txt:
        self.format(x, escape)
    elif isinstance(txt, Table):
      self.format_table(txt)
