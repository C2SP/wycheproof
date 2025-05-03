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

import math

class Sample:
  '''A 1-dimensional sample'''
  def __init__(self, store_samples=False):
    self.store_samples = False
    self.samples = []
    self.n = 0
    self.sum = 0
    self.sumsqr = 0
    self.min = None
    self.max = None

  def append(self, x):
    if self.store_samples:
      self.samples.append(x)
    self.n += 1
    self.sum += x
    self.sumsqr += x * x
    if self.min is not None:
      self.min = min(self.min, x)
    else:
      self.min = x
    if self.max is not None:
      self.max = max(self.max, x)
    else:
      self.max = x
   
  def avg(self):
    return self.sum / self.n

  def var(self):
    return (self.sumsqr - self.sum **2 / self.n) / (self.n - 1)

  def std_dev(self):
    return math.sqrt(self.var())

  def cv(self):
    return self.std_dev() / self.avg()

  def indexOfDispersion(self):
    return self.var() / self.avg()

  def description(self):
    return 'samples:%d avg:%s std:%s, cv:%s iod:%s' % (self.n, self.avg(),
        self.std_dev(), self.cv(), self.indexOfDispersion()) 

  __str__ = description


class Sample2dim:
  '''A two dimensional sample.'''

  def __init__(self, store_samples=False):
    self.x = Sample(store_samples)
    self.y = Sample(store_samples)
    self.xy = Sample(store_samples=False)

  def append(self, x, y):
    self.x.append(x)
    self.y.append(y)
    self.xy.append(x*y)

  def cov(self):
    return self.xy.avg() - self.x.avg() * self.y.avg()

  def correlation_coefficient(self):
    n = self.xy.n
    num = self.xy.sum*n - self.x.sum * self.y.sum
    densqr = (n*self.x.sumsqr - self.x.sum**2) * (n*self.y.sumsqr - self.y.sum**2)
    return num / math.sqrt(densqr)

  def description(self):
    return 'samples:%d cov:%s corr_coeff:%s' % (self.x.n,
        self.cov(), self.correlation_coefficient())

  __str__ = description


