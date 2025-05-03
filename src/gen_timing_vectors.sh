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

# Generation of vectors for timing measurments.

# Default version for python
# Requires probably at least version 3.8. The code does not try to
# be backwards compatible. We just have to be able to generate the vectors
# somehow.
# The main requirement here is that it supports cryptography.hazmat.
# SHA-3 and OrderedDicts by default
PYTHON=python3
start=$(date +'%s')

# Defining what python version to use:
# Unfortunately python changes a lot from version to version.
# Sometimes the test vector generation has to use multiple versions,
# so that required features are available.

DIR=/google/src/cloud/bleichen/keymaster1/google3/experimental/users/bleichen/wycheproof/
OUT_DIR=$DIR/timing

# Options:
# For internal versions use
# OPT=--alpha
# For release leave empty and use
OPT=

rm $OUT_DIR/*_timing.json

# Test vectors for ECDH
gen_ecdh() {
  $PYTHON gen_ecdh_timing.py $OPT --encoding=asn --curve=$1 --out=$OUT_DIR/ecdh_$1_timing.json &
}

gen_ecdh "secp224r1"
gen_ecdh "secp256r1"
gen_ecdh "secp256k1"
gen_ecdh "secp384r1"
gen_ecdh "secp521r1"

# Make a jar using these options:
# c create a jar
# v verbose
# f make a file
wait
cd $DIR

if [ "$OPT" == "--alpha" ]
then
  jar cvf timing_alpha.jar timing/*.json
else
  jar cvf timing.jar timing/*.json
fi

stop=$(date +'%s')
echo "Elapsed: $(( stop - start )) sec"

