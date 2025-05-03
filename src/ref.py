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
from html.parser import HTMLParser
from urllib.request import urlopen

class RFC:
  def __init__(self, num: int):
    self.num = num
    self.doc = None

  def load(self):
    from urllib.request import urlopen
    if self.doc is not None:
      return
    assert isinstance(self.num, int)
    url = "https://tools.ietf.org/rfc/rfc%d.txt" % self.num
    r = urlopen(url)
    self.doc = r.read()

  def lines(self) -> typing.List[bytes]:
    if self.doc is None:
      raise ValueError("Document not loaded")
    return self.doc.split(b'\n')

class IacrEprint:
  def __init__(self, year: int, num: int):
    self.year = year
    self.num = num
    self.abstract = None
    self.bibtex = None

  def read_url(self, url: str) -> bytes:
    r = urlopen(url)
    return r.read()

  def url_abstract(self):
    '''Returns the url for the papers abstract'''
    return "https://eprint.iacr.org/%d/%03d" % (self.year, self.num)

  def url_bibtex(self):
    '''Returns the urls for the bibtex entry'''
    return ("https://eprint.iacr.org/eprint-bin/cite.pl?entry=%d/%03d"
                % (self.year, self.num))

  def citation(self):
    if self.bibtex is None:
      # Just try reading the entry once.
      self.bibtex = ''
      url = self.url_bibtex()
      # I'm using the following assumptions here:
      # eprint citations are using XML.
      # The default encoding for XML is UTF-8.
      # If another encoding is used then the header should use
      # something like <?xml version="1.0" encoding="ISO-8859-9"?>
      html = self.read_url(url).decode('utf-8')
      a = html.find('@')
      b = html.rfind('}')
      assert 0 <= a < b
      self.bibtex = html[a:b+1]
    return self.bibtex

  def load(self):  
    '''Just load the abstract'''
    if self.abstract is not None:
      return
    assert isinstance(self.num, int)
    url = self.url_abstract()
    r = urlopen(url)
    self.abstract = r.read().decode('ascii')

