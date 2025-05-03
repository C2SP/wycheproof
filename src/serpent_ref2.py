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

import util
#!/usr/local/bin/python

# $Id: serpref.py,v 1.19 1998/09/02 21:28:02 fms Exp $
#
# Python reference implementation of Serpent.
#
# Written by Frank Stajano,
# Olivetti Oracle Research Laboratory <http://www.orl.co.uk/~fms/> and
# Cambridge University Computer Laboratory <http://www.cl.cam.ac.uk/~fms27/>.
#
# (c) 1998 Olivetti Oracle Research Laboratory (ORL)
#
# Original (Python) Serpent reference development started on 1998 02 12.
# C implementation development started on 1998 03 04.
#
# Serpent cipher invented by Ross Anderson, Eli Biham, Lars Knudsen.
# Serpent is a candidate for the Advanced Encryption Standard.

# --------------------------------------------------------------

"""This is an illustrative reference implementation of the Serpent cipher
invented by Eli Biham, Ross Anderson, Lars Knudsen. It is written for the
human reader more than for the machine and, as such, it is optimised for
clarity rather than speed. ("Premature optimisation is the root of all
evil.")
It can print out all the intermediate results (such as the subkeys) for a
given input and key so that implementers debugging erroneous code can
quickly verify which one of the building blocks is giving the wrong
answers.
This version implements Serpent-1, i.e. the variant defined in the final
submission to NIST.
"""


BitString = str  # A string of '01', in little endian order

# --------------------------------------------------------------
# My own additions
# --------------------------------------------------------------
class Serpent:
    #class to
    @util.type_check
    def __init__(self, key: bytes):
        rawKey = bytesToBitString(key)
        self.userKey = makeLongKey(rawKey)

    @util.type_check
    def encrypt(self, block: bytes) -> bytes:
        plainText = bytesToBitString(block)
        cipherText = encrypt(plainText, self.userKey)
        return bitstring2bytes(cipherText)[::-1]

    @util.type_check
    def decrypt(self, block: bytes) -> bytes:
        cipherText = bytesToBitString(block)
        plainText = decrypt(cipherText, self.userKey)
        return bitstring2bytes(plainText)[::-1]

    def get_block_size(self) -> int:
        return 16

# --------------------------------------------------------------
# Functions used in the formal description of the cipher

def S(box, input):
    """Apply S-box number 'box' to 4-bit bitstring 'input' and return a
    4-bit bitstring as the result."""

    return SBoxBitstring[box%8][input]
    # There used to be 32 different S-boxes in serpent-0. Now there are
    # only 8, each of which is used 4 times (Sboxes 8, 16, 24 are all
    # identical to Sbox 0, etc). Hence the %8.

def SInverse(box, output):
    """Apply S-box number 'box' in reverse to 4-bit bitstring 'output' and
    return a 4-bit bitstring (the input) as the result."""

    return SBoxBitstringInverse[box%8][output]


def SHat(box, input):
    """Apply a parallel array of 32 copies of S-box number 'box' to the
    128-bit bitstring 'input' and return a 128-bit bitstring as the
    result."""

    result = ""
    for i in range(32):
        result = result + S(box, input[4*i:4*(i+1)])
    return result

def SHatInverse(box, output):
    """Apply, in reverse, a parallel array of 32 copies of S-box number
    'box' to the 128-bit bitstring 'output' and return a 128-bit bitstring
    (the input) as the result."""

    result = ""
    for i in range(32):
        result = result + SInverse(box, output[4*i:4*(i+1)])
    return result


def SBitslice(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    to the 4 input bits coming from the current position in each of the
    items in 'words'; and put the 4 output bits in the corresponding
    positions in the output words."""

    result = ["", "", "", ""]
    for i in range(32): # ideally in parallel
        quad = S(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result

def SBitsliceInverse(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    in reverse to the 4 output bits coming from the current position in
    each of the items in the supplied 'words'; and put the 4 input bits in
    the corresponding positions in the returned words."""

    result = ["", "", "", ""]
    for i in range(32): # ideally in parallel
        quad = SInverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def LT(input):
    """Apply the table-based version of the linear transformation to the
    128-bit string 'input' and return a 128-bit string as the result."""

    if len(input) != 128:
        raise(ValueError, "input to LT is not 128 bit long")

    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result

def LTInverse(output):
    """Apply the table-based version of the inverse of the linear
    transformation to the 128-bit string 'output' and return a 128-bit
    string (the input) as the result."""

    if len(output) != 128:
        raise (ValueError, "input to inverse LT is not 128 bit long")

    result = ""
    for i in range(len(LTTableInverse)):
        inputBit = "0"
        for j in LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result

def rotate_left(x: int, bits):
  return ((x << bits) ^ (x >> (32 - bits))) & 0xffffffff

def rotate_right(x: int, bits):
  return rotate_left(x, 32-bits)

def shift_left(x: int, bits):
  return (x << bits) & 0xffffffff
  
def LTBitSlice(X: list[int]):
    X[0] = rotate_left(X[0], 13)
    X[2] = rotate_left(X[2], 3)
    X[1] ^= X[0] ^ X[2]
    X[3] ^= X[2] ^shift_left(X[0], 3)
    X[1] = rotate_left(X[1], 1)
    X[3] = rotate_left(X[3], 7)
    X[0] ^= X[1] ^ X[3]
    X[2] ^= X[3] ^ shift_left(X[1], 7)
    X[0] = rotate_left(X[0], 5)
    X[2] = rotate_left(X[2], 22)

def LTBitSliceInverse(X: list[int]):
    """Apply, in reverse, the equations-based version of the linear
    transformation to 'X', a list of 4 32-bit bitstrings, least significant
    bitstring first, and return another list of 4 32-bit bitstrings as the
    result."""

    X[2] = rotate_right(X[2], 22)
    X[0] = rotate_right(X[0], 5)
    X[2] ^= X[3] ^ shift_left(X[1], 7)
    X[0] ^= X[1] ^ X[3]
    X[3] = rotate_right(X[3], 7)
    X[1] = rotate_right(X[1], 1)
    X[3] ^= X[2] ^ shift_left(X[0], 3)
    X[1] ^= X[0] ^ X[2]
    X[2] = rotate_right(X[2], 3)
    X[0] = rotate_right(X[0], 13)


    
def LTBitslice(X: list[BitString]) -> list[BitString]:
    """Apply the equations-based version of the linear transformation to
    'X', a list of 4 32-bit bitstrings, least significant bitstring first,
    and return another list of 4 32-bit bitstrings as the result."""
    
    Y = [bitstring2int(x) for x in X]
    LTBitSlice(Y)
    return [bitstring(x, 32) for x in Y]

def LTBitsliceInverse(X):
    """Apply, in reverse, the equations-based version of the linear
    transformation to 'X', a list of 4 32-bit bitstrings, least significant
    bitstring first, and return another list of 4 32-bit bitstrings as the
    result."""

    Y = [bitstring2int(x) for x in X]
    LTBitSliceInverse(Y)
    return [bitstring(x, 32) for x in Y]


def IP(input):
    """Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(IPTable, input)

def FP(input):
    """Apply the Final Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(FPTable, input)


def IPInverse(output):
    """Apply the Initial Permutation in reverse."""

    return FP(output)

def FPInverse(output):
    """Apply the Final Permutation in reverse."""

    return IP(output)


def applyPermutation(permutationTable, input):
    """Apply the permutation specified by the 128-element list
    'permutationTable' to the 128-bit bitstring 'input' and return a
    128-bit bitstring as the result."""

    if len(input) != len(permutationTable):
        raise (ValueError, "input size (%d) doesn't match perm table size (%d)"\
              % (len(input), len(permutationTable)))

    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result


def R(i, BHati, KHat):
    """Apply round 'i' to the 128-bit bitstring 'BHati', returning another
    128-bit bitstring (conceptually BHatiPlus1). Do this using the
    appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    xored = xor(BHati, KHat[i])
    SHati = SHat(i, xored)
    if 0 <= i <= r-2:
        BHatiPlus1 = LT(SHati)
    elif i == r-1:
        BHatiPlus1 = xor(SHati, KHat[r])
    else:
        raise ValueError( "round %d is out of 0..%d range" % (i, r-1))

    return BHatiPlus1


def RInverse(i, BHatiPlus1, KHat):
    """Apply round 'i' in reverse to the 128-bit bitstring 'BHatiPlus1',
    returning another 128-bit bitstring (conceptually BHati). Do this using
    the appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    if 0 <= i <= r-2:
        SHati = LTInverse(BHatiPlus1)
    elif i == r-1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r-1))
    xored = SHatInverse(i, SHati)
    BHati = xor(xored, KHat[i])
    return BHati


def RBitslice(i: int, Bi: BitString, K: list[BitString]) -> BitString:
    """Apply round 'i' (bitslice version) to the 128-bit bitstring 'Bi' and
    return another 128-bit bitstring (conceptually B i+1). Use the
    appropriately numbered subkey(s) from the 'K' list of 33 128-bit
    bitstrings."""

    # 1. Key mixing
    xored = xor (Bi, K[i])
    # 2. S Boxes
    Si = SBitslice(i, quadSplit(xored))
    # Input and output to SBitslice are both lists of 4 32-bit bitstrings

    # 3. Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        BiPlus1 = xor(quadJoin(Si), K[r])
    else:
        BiPlus1 = quadJoin(LTBitslice(Si))
    # BIPlus1 is a 128-bit bitstring

    return BiPlus1


def RBitsliceInverse(i, BiPlus1, K):
    """Apply the inverse of round 'i' (bitslice version) to the 128-bit
    bitstring 'BiPlus1' and return another 128-bit bitstring (conceptually
    B i). Use the appropriately numbered subkey(s) from the 'K' list of 33
    128-bit bitstrings."""

    # 3. Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        Si = quadSplit(xor(BiPlus1, K[r]))
    else:
        Si = LTBitsliceInverse(quadSplit(BiPlus1))
    # SOutput (same as LTInput) is a list of 4 32-bit bitstrings

    # 2. S Boxes
    xored = SBitsliceInverse(i, Si)
    # SInput and SOutput are both lists of 4 32-bit bitstrings

    # 1. Key mixing
    Bi = xor (quadJoin(xored), K[i])

    return Bi



def encrypt(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the normal algorithm, and return a 128-bit ciphertext
    bitstring."""

    K, KHat = makeSubkeys(userKey)

    BHat = IP(plainText) # BHat_0 at this stage
    for i in range(r):
        BHat = R(i, BHat, KHat) # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    return FP(BHat)


def encryptBitslice(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the bitslice algorithm, and return a 128-bit ciphertext
    bitstring."""

    K, KHat = makeSubkeys(userKey)

    B = plainText # B_0 at this stage
    for i in range(r):
        B = RBitslice(i, B, K) # Produce B_i+1 from B_i

    return B

def decrypt(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the normal algorithm, and return a 128-bit
    plaintext bitstring."""

    K, KHat = makeSubkeys(userKey)

    BHat = FPInverse(cipherText) # BHat_r at this stage
    for i in range(r-1, -1, -1): # from r-1 down to 0 included
        BHat = RInverse(i, BHat, KHat) # Produce BHat_i from BHat_i+1
    # BHat is now _0
    plainText = IPInverse(BHat)

    return plainText


def decryptBitslice(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the bitslice algorithm, and return a 128-bit
    plaintext bitstring."""

    K, KHat = makeSubkeys(userKey)

    B = cipherText # B_r at this stage
    for i in range(r-1, -1, -1): # from r-1 down to 0 included
        B = RBitsliceInverse(i, B, K) # Produce B_i from B_i+1
    # B is now _0

    return B


def makeSubkeys(userKey):
    """Given the 256-bit bitstring 'userKey' (shown as K in the paper, but
    we can't use that name because of a collision with K[i] used later for
    something else), return two lists (conceptually K and KHat) of 33
    128-bit bitstrings each."""

    # Because in Python I can't index a list from anything other than 0,
    # I use a dictionary instead to legibly represent the w_i that are
    # indexed from -8.

    # We write the key as 8 32-bit words w-8 ... w-1
    # ENOTE: w-8 is the least significant word
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i+8)*32:(i+9)*32]

    # We expand these to a prekey w0 ... w131 with the affine recurrence
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i-8], w[i-5], w[i-3], w[i-1],
                bitstring(phi, 32), bitstring(i,32)),
            11)

    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(r+1):
        whichS = (r + 3 - i) % r
        k[0+4*i] = ""
        k[1+4*i] = ""
        k[2+4*i] = ""
        k[3+4*i] = ""
        for j in range(32): # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0+4*i][j] + w[1+4*i][j] + w[2+4*i][j] + w[3+4*i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l+4*i] = k[l+4*i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(33):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4*i] + k[4*i+1] + k[4*i+2] + k[4*i+3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))

    return K, KHat


def makeLongKey(k: BitString) -> BitString:
    """Take a key k in bitstring format. Return the long version of that
    key."""

    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        raise ValueError("Invalid key length (%d bits)" % l)

    if l == 256:
        return k
    else:
        return k + "1" + "0"*(256 -l -1)

# --------------------------------------------------------------
# Generic bit-level primitives

# Internally, we represent the numbers manipulated by the cipher in a
# format that we call 'bitstring'. This is a string of "0" and "1"
# characters containing the binary representation of the number in
# little-endian format (so that subscripting with an index of i gives bit
# number i, corresponding to a weight of 2^i). This representation is only
# defined for nonnegative numbers (you can see why: think of the great
# unnecessary mess that would result from sign extension, two's complement
# and so on).  Example: 10 decimal is "0101" in bitstring format.

@util.type_check
def bitstring(n: int, length: int) -> str:
    """Converts an integer into a bitstring in little endian order.
    EXAMPLE: bitstring(10, 8) -> "01010000"
    """

    res = ""
    for _ in range(length):
      res += "01"[n % 2]
      n >>= 1
    assert n == 0
    return res

def bitstring2int(s: str) -> int:
  return int(s[::-1], 2)

def binaryXor(n1: bitstring, n2: bitstring):
    """Return the xor of two bitstrings of equal length as another
    bitstring of the same length.
    EXAMPLE: binaryXor("10010", "00011") -> "10001"
    """
    assert(len(n1) == len(n2))
    if len(n1) != len(n2):
        raise ValueError("can't xor bitstrings of different " + \
              "lengths (%d and %d)" % (len(n1), len(n2)))
    # We assume that they are genuine bitstrings instead of just random
    # character strings.

    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result


def xor(*args):
    """Return the xor of an arbitrary number of bitstrings of the same
    length as another bitstring of the same length.
    EXAMPLE: xor("01", "11", "10") -> "00"
    """

    if args == []:
        raise ValueError("at least one argument needed")

    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result


def rotateLeft(input, places):
    """Take a bitstring 'input' of arbitrary length. Rotate it left by
    'places' places. Left means that the 'places' most significant bits are
    taken out and reinserted as the least significant bits. Note that,
    because the bitstring representation is little-endian, the visual
    effect is actually that of rotating the string to the right.
    EXAMPLE: rotateLeft("000111", 2) -> "110001"
    """

    p = places % len(input)
    return input[-p:] + input[:-p]

def rotateRight(input, places):
    return rotateLeft(input, -places)

def shiftLeft(input, p):
    """Take a bitstring 'input' of arbitrary length. Shift it left by 'p'
    places. Left means that the 'p' most significant bits are shifted out
    and dropped, while 'p' 0s are inserted in the the least significant
    bits. Note that, because the bitstring representation is little-endian,
    the visual effect is actually that of shifting the string to the
    right. Negative values for 'p' are allowed, with the effect of shifting
    right instead (i.e. the 0s are inserted in the most significant bits).
    EXAMPLE: shiftLeft("000111", 2) -> "000001"
             shiftLeft("000111", -2) -> "011100"
    """

    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return  input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else: # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]

def shiftRight(input, p):
    """Take a bitstring 'input' and shift it right by 'p' places. See the
    doc for shiftLeft for more details."""

    return shiftLeft(input, -p)


# --------------------------------------------------------------
# Hex conversion functions

# For I/O we use BIG-ENDIAN hexstrings. Do not get confused: internal stuff
# is LITTLE-ENDIAN bitstrings (so that digit i has weight 2^i) while
# external stuff is in BIG-ENDIAN hexstrings (so that it's shorter and it
# looks like the numbers you normally write down). The external (I/O)
# representation is the same as used by the C reference implementation.

bin2hex = {
    # Given a 4-char bitstring, return the corresponding 1-char hexstring
    "0000": "0", "1000": "1", "0100": "2", "1100": "3",
    "0010": "4", "1010": "5", "0110": "6", "1110": "7",
    "0001": "8", "1001": "9", "0101": "a", "1101": "b",
    "0011": "c", "1011": "d", "0111": "e", "1111": "f",
    }

# Make the reverse lookup table too
hex2bin = {}
for (bin, hex) in bin2hex.items():
    hex2bin[hex] = bin


def bitstring2hexstring(b):
    """Take bitstring 'b' and return the corresponding hexstring."""

    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4-(l%4))
    for i in range(0, len(b), 4):
        result = result+bin2hex[b[i:i+4]]
    return reverseString(result)

@util.type_check
def bitstring2bytes(b: BitString) -> bytes:
  return bytes.fromhex(bitstring2hexstring(b))

def hexstring2bitstring(h: str)-> str:
    """Take hexstring 'h' and return the corresponding bitstring."""

    result = ""
    for c in reverseString(h):
        result = result + hex2bin[c]
    return result

def reverseString(s):
    return s[::-1]

# --------------------------------------------------------------
# Format conversions

def quadSplit(b128):
    """Take a 128-bit bitstring and return it as a list of 4 32-bit
    bitstrings, least significant bitstring first."""

    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + len(b128))

    result = []
    for i in range(4):
        result.append(b128[(i*32):(i+1)*32])
    return result

def quadSplitInt(b128: BitString):
    return [bitstring2int(x) for x in quadSplit(b128)]

def quadJoin(l4x32):
    """Take a list of 4 32-bit bitstrings and return it as a single 128-bit
    bitstring obtained by concatenating the internal ones."""

    if len(l4x32) != 4:
        raise ValueError("need a list of 4 bitstrings, not " + len(l4x32))

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]

def quadJoinInt(l4x32):
  return quadJoin([bitstring(x, 32) for x in l4x32])

# --------------------------------------------------------------
# Constants
phi = 0x9e3779b9
r = 32
# --------------------------------------------------------------
# Data tables


# Each element of this list corresponds to one S-box. Each S-box in turn is
# a list of 16 integers in the range 0..15, without repetitions. Having the
# value v (say, 14) in position p (say, 0) means that if the input to that
# S-box is the pattern p (0, or 0x0) then the output will be the pattern v
# (14, or 0xe).
SBoxDecimalTable = [
    [ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 ], # S0
    [15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 ], # S1
    [ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 ], # S2
    [ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 ], # S3
    [ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 ], # S4
    [15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 ], # S5
    [ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 ], # S6
    [ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 ], # S7
    ]
# NB: in serpent-0, this was a list of 32 sublists (for the 32 different
# S-boxes derived from DES). In the final version of Serpent only 8 S-boxes
# are used, with each one being reused 4 times.


# Make another version of this table as a list of dictionaries: one
# dictionary per S-box, where the value of the entry indexed by i tells you
# the output configuration when the input is i, with both the index and the
# value being bitstrings.  Make also the inverse: another list of
# dictionaries, one per S-box, where each dictionary gets the output of the
# S-box as the key and gives you the input, with both values being 4-bit
# bitstrings.
SBoxBitstring = []
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)

IPTable = [(i // 4) + 32 * (i % 4) for i in range(128)]
FPTable = [(i // 32) + 4 * (i %32) for i in range(128)]


# The Linear Transformation is represented as a list of 128 lists, one for
# each output bit. Each one of the 128 lists is composed of a variable
# number of integers in 0..127 specifying the positions of the input bits
# that must be XORed together (say, 72, 144 and 125) to yield the output
# bit corresponding to the position of that list (say, 1).
LTTable = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
    ]

# The following table is necessary for the non-bitslice decryption.
LTTableInverse = [
    [53, 55, 72],
    [1, 5, 20, 90],
    [15, 102],
    [3, 31, 90],
    [57, 59, 76],
    [5, 9, 24, 94],
    [19, 106],
    [7, 35, 94],
    [61, 63, 80],
    [9, 13, 28, 98],
    [23, 110],
    [11, 39, 98],
    [65, 67, 84],
    [13, 17, 32, 102],
    [27, 114],
    [1, 3, 15, 20, 43, 102],
    [69, 71, 88],
    [17, 21, 36, 106],
    [1, 31, 118],
    [5, 7, 19, 24, 47, 106],
    [73, 75, 92],
    [21, 25, 40, 110],
    [5, 35, 122],
    [9, 11, 23, 28, 51, 110],
    [77, 79, 96],
    [25, 29, 44, 114],
    [9, 39, 126],
    [13, 15, 27, 32, 55, 114],
    [81, 83, 100],
    [1, 29, 33, 48, 118],
    [2, 13, 43],
    [1, 17, 19, 31, 36, 59, 118],
    [85, 87, 104],
    [5, 33, 37, 52, 122],
    [6, 17, 47],
    [5, 21, 23, 35, 40, 63, 122],
    [89, 91, 108],
    [9, 37, 41, 56, 126],
    [10, 21, 51],
    [9, 25, 27, 39, 44, 67, 126],
    [93, 95, 112],
    [2, 13, 41, 45, 60],
    [14, 25, 55],
    [2, 13, 29, 31, 43, 48, 71],
    [97, 99, 116],
    [6, 17, 45, 49, 64],
    [18, 29, 59],
    [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120],
    [10, 21, 49, 53, 68],
    [22, 33, 63],
    [10, 21, 37, 39, 51, 56, 79],
    [105, 107, 124],
    [14, 25, 53, 57, 72],
    [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83],
    [0, 109, 111],
    [18, 29, 57, 61, 76],
    [30, 41, 71],
    [18, 29, 45, 47, 59, 64, 87],
    [4, 113, 115],
    [22, 33, 61, 65, 80],
    [34, 45, 75],
    [22, 33, 49, 51, 63, 68, 91],
    [8, 117, 119],
    [26, 37, 65, 69, 84],
    [38, 49, 79],
    [26, 37, 53, 55, 67, 72, 95],
    [12, 121, 123],
    [30, 41, 69, 73, 88],
    [42, 53, 83],
    [30, 41, 57, 59, 71, 76, 99],
    [16, 125, 127],
    [34, 45, 73, 77, 92],
    [46, 57, 87],
    [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20],
    [38, 49, 77, 81, 96],
    [50, 61, 91],
    [38, 49, 65, 67, 79, 84, 107],
    [5, 7, 24],
    [42, 53, 81, 85, 100],
    [54, 65, 95],
    [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28],
    [46, 57, 85, 89, 104],
    [58, 69, 99],
    [46, 57, 73, 75, 87, 92, 115],
    [13, 15, 32],
    [50, 61, 89, 93, 108],
    [62, 73, 103],
    [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36],
    [54, 65, 93, 97, 112],
    [66, 77, 107],
    [54, 65, 81, 83, 95, 100, 123],
    [21, 23, 40],
    [58, 69, 97, 101, 116],
    [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127],
    [25, 27, 44],
    [62, 73, 101, 105, 120],
    [74, 85, 115],
    [3, 62, 73, 89, 91, 103, 108],
    [29, 31, 48],
    [66, 77, 105, 109, 124],
    [78, 89, 119],
    [7, 66, 77, 93, 95, 107, 112],
    [33, 35, 52],
    [0, 70, 81, 109, 113],
    [82, 93, 123],
    [11, 70, 81, 97, 99, 111, 116],
    [37, 39, 56],
    [4, 74, 85, 113, 117],
    [86, 97, 127],
    [15, 74, 85, 101, 103, 115, 120],
    [41, 43, 60],
    [8, 78, 89, 117, 121],
    [3, 90],
    [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64],
    [12, 82, 93, 121, 125],
    [7, 94],
    [0, 23, 82, 93, 109, 111, 123],
    [49, 51, 68],
    [1, 16, 86, 97, 125],
    [11, 98],
    [4, 27, 86, 97, 113, 115, 127],
]


def convertToBitString(input: str) -> BitString:
    return bytesToBitString(bytes.fromhex(input))

@util.type_check
def bytesToBitString(b: bytes) -> BitString:
    return hexstring2bitstring(b[::-1].hex())

SERPENT_KTV = [
  {"key": "0000000000000000000000000000000000000000000000000000000000000000",
   "pt":  "00000000000000000000000000000000",
   "ct":  "49672ba898d98df95019180445491089"},

  {"key": "8000000000000000000000000000000000000000000000000000000000000000",
   "pt":  "00000000000000000000000000000000",
   "ct":  "a223aa1288463c0e2be38ebd825616c0"},
   
   {"key" : "00112233445566778899aabbccddeeff",
    "pt" : "00000000000000000000000000000000",
    "ct" : "8b3e43c04d285933abde6c2e56d70126"
   },

   {"key" : "00112233445566778899aabbccddeeff",
    "pt" : "0123456789abcdef0011223344556677",
    "ct" : "7b8901685a9d2815311b673ff184501e"
   },

   {"key" :"0123456789abcdef0011223344556677",
    "pt" : "0123456789abcdef0011223344556677",
    "ct" : "9049578f7e2c8db30b08846a39778b20"
   },

]

def test_ktv():
  errors = 0
  for t in SERPENT_KTV:
     print('----------')
     print(t)
     keylen = 4 * len(t["key"])
     k = convertToBitString(t["key"])
     k = makeLongKey(k)
     p = convertToBitString(t["pt"])
     c = convertToBitString(t["ct"])
     c2 = encryptBitslice(p, k)
     p2 = decryptBitslice(c2, k)
     print('c ',bitstring2hexstring(c))
     print('c2',bitstring2hexstring(c2))
     print('p2',bitstring2hexstring(p2))
     print('p',bitstring2hexstring(p))
     if c != c2:
       errors += 1
  assert errors == 0

def test_ktv2():
  errors = 0
  for t in SERPENT_KTV:
     print('----------')
     print(t)
     key = bytes.fromhex(t["key"])
     p = bytes.fromhex(t["pt"])
     c = bytes.fromhex(t["ct"])
     cipher = Serpent(key)
     c2 = cipher.encrypt(p)
     p2 = cipher.decrypt(c2)
     print(p.hex())
     print(p2.hex())
     print(c.hex())
     print(c2.hex())
     if c != c2:
       errors += 1
  assert errors == 0

if __name__ == "__main__":
    test_ktv2()
    test_ktv()

