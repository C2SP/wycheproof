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

"""
EW : y
2 = x
3 − 3763200000x − 78675968000000.
Endomorphism. The endomorphism ψ can obtained using the method detailed above. We obtain the following expression:
ψW(x, y) = u 2·x^2 + 44800x + 2257920000 x + 44800,
u3 · y · x^2 + 2 · 44800x + t0(x + 44800)^2.

u=0x50281ac0f92fc1b20fd897a16bf2b9e132bdcb06721c589296cf82245cf9382d
t0=0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffef10be001.

Subgroup generator. The generator of the p253-order subgroup is computed
by finding the lexicographically smallest valid x-coordinate of a point of the
curve, and scaling it by the cofactor 4 such that the result is not the point at
infinity. From a point with x = 2, we obtain a generator EW (xW , yW ) where:

xW=a76451786f95a802c0982bbd0abd68e41b92adc86c8859b4f44679b21658710
yW=44d150c8b4bd14f79720d021a839e7b7eb4ee43844b30243126a72ac2375490a.

3.2 Twisted Edwards curve
Curve equation. Bandersnatch can also be represented in twisted Edwards
coordinates, where the group law is complete. In this model, the Bandersnatch
curve can be defined by the equation
ETE : −5x^2+y^2 = 1+d x^2 y^2,
d = 138827208126141220649022263972958607803 / 171449701953573178309673572579671231137.
Twisted Edwards group law is more efficient with a coefficient a = −1 (see [7]
for details). In our case, −5 is not a square in Fp. Thus, the curve with equation
−x^2 + y^2 = 1 − dx^2y^2/5 is the quadratic twist of Bandersnatch. We provide
a representation with a = −5, leading to a slightly more expensive group law
because multiplying by −5 is more expensive than a multiplication by −1, but
this cost will be neglected compared to the improvement of the GLV method.
See Section 4 for details.

5 Endomorphism.
From this representation, we exhibit the degree 2 endomorphism in twisted Edwards coordinates:
ψTE(x, y, z) = (f(y)h(y), g(y)xy, h(y)xy) 
f(y) = c(z^2 − y^2),
g(y) = b(y^2 + bz^2),
h(y) = y^2 − bz^2
.
b=0x52c9f28b828426a561f00d3a63511a882ea712770d9af4d6ee0f014d172510b4
c=0x6cc624cf865457c3a97c6efd6c17d1078456abcfff36f4e9515c806cdf650b3d.

This map can be computed in 3 additions and 9 multiplications by first computing xy, y^2
, z^2 and bz^2.
Subgroup generator. The generator of the p253-order subgroup obtained in
Section 3.1 has twisted coordinates of the form ETE(xTE, yTE, 1) with

xTE=29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18
yTE=2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166.

3.3 Montgomery curve
Curve equation. A twisted Edwards curve is always birationally equivalent
to a Montgomery curve. We obtain the mapping between these two representations following [8].
While the twisted Edwards model fits better for Fp circuit
arithmetic and more generally for the zero-knowledge proof context, we provide
here the Montgomery version because the scalar multiplication is more efficient
in this model:
EM : By2 = x^3 + Ax^2 + x

B=0x300c3385d13bedb7c9e229e185c4ce8b1dd3b71366bb97c30855c0aa41d62727
A=0x4247698f4e32ad45a293959b4ca17afa4a2d2317e4c6ce5023e1fd63d1b5de98.

Endomorphism. 

Montgomery curves allow efficient scalar multiplication using the Montgomery ladder. We provide here the endomorphism ψ in this
model:
ψM(x, −, z) = (−(x − z)
2 − cxz, −, 2xz)
c=0x4247698f4e32ad45a293959b4ca17afa4a2d2317e4c6ce5023e1fd63d1b5de9a.
Subgroup generator. The generator of the p253-order subgroup given above
is of the form EM(xM, −, 1) with:
xM=67c5b5fed18254e8acb66c1e38f33ee0975ae6876f9c5266a883f4604024b3b8.
"""
