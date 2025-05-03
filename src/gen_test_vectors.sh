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

# Test vector generation. Needs at least Python 3.8.

# Parsing parameters
VERSION=internal_update
OPT=--poolsize=16
while getopts ":air" opt; do
  case ${opt} in
    a )
      VERSION=alpha
      echo "Including test vectors in alpha status"
      ;;
    i )
      VERSION=internal
      echo "Generating internal version of test vectors"
      ;;
    r )
      VERSION=release
      echo "Generating test vectors for release"
      ;;
    \? )
      echo "Invalid parameter"
      echo "Usage: gen_test_vectors [-adir]"
      echo "-a generate test vectors in alpha state."
      echo "-r generate release version."
      echo "-i generate the internal version."
      exit 1
      ;;
  esac
done

start=$(date +'%s')

# Python version.
#
# Python changes a lot from version to version. I'm not trying to keep
# the code version independent.
#
# The code for generating the test vectors requires version 3.8 or higher.
# The main requirement here is that it supports:
# - cryptography.hazmat
# - SHA-3, SHAKE
# - a recent version for type hints
PYTHON=python3

if [ "$VERSION" == "alpha" ]
then
  DIR=/google/src/cloud/bleichen/keymaster1/google3/experimental/users/bleichen/wycheproof
  OUT_DIR=$DIR/testvectors
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=3600 --version=$VERSION
elif [ "$VERSION" == "internal" ]
then
  DIR=/google/src/cloud/bleichen/keymaster1/google3/third_party/wycheproof/internal
  OUT_DIR=$DIR/testvectors
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=3600 --version=$VERSION
elif [ "$VERSION" == "release" ]
then
  DIR=/google/src/cloud/bleichen/keymaster1/google3/third_party/wycheproof/
  OUT_DIR=$DIR/testvectors_v1
  rm $OUT_DIR/*_test.json
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=0 --version=$VERSION
  cd $DIR
  jar cvf $DIR/testvectors.jar $OUTDIR/*.json
fi

stop=$(date +'%s')
echo "Elapsed: $(( stop - start )) sec"

