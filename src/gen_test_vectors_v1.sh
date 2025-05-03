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

VERSION=internal
OP=continue

while getopts ":aol" opt; do
  case ${opt} in
    a )
      OP=all
      echo "Regenerating all test vectors"
      ;;
    o )
      OP=old
      echo "Regenerating old vectors"
      ;;
    l )
      OP=list
      echo "Listing missing files"
      ;;
    \? )
      echo "Invalid parameter"
      echo "Usage: gen_test_vectors [-a]"
      echo "-a generate all test vectors."
      exit 1
      ;;
  esac
done

start=$(date +'%s')

# needs at least version 3.9
PYTHON=python3
VERSION=release
DIR=/google/src/cloud/bleichen/keymaster1/google3/third_party/wycheproof/
OUT_DIR=$DIR/testvectors_v1
OPT=--poolsize=12

if [ "$OP" == "list" ]
then
  $PYTHON gen_test_vectors.py --dir=$OUT_DIR --version=internal --list
  exit
fi

if [ "$OP" == "old" ]
then
  AGE=86400
else
  AGE=0
fi

aead() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_aegis
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_gcm
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_aes_gcm_siv
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_aes_siv_aead
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_aes_eax
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_morus
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_chacha
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_xchacha
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_ascon
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_jwa_aes_cbc_hmac
}

daead() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_aes_siv

}

signatures() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_rsa_signature
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_dsa
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_eddsa
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_rsa_pss
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_ecdsa
}

pk_enc() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_rsaes_pkcs1
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_rsa_oaep
}

mac() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_cmac
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_gmac
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_vmac
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_hmac
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_kmac
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_sip_hash
}

dh() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_ecdh
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_xdh  
}

regen() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_ccm
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_rsa_oaep
}

misc() {
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_fpe
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_eccurves
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_kwp
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_kw
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_primetest
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_xts
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_xdh
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_cbc_pkcs5
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_hkdf
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_pbkdf
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_pbe
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_primetest
}

new() {
  echo new
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION --gen=gen_pbe
}

all() {
  echo all
  $PYTHON gen_test_vectors.py $OPT --dir=$OUT_DIR --age=$AGE --version=$VERSION
}

if [ "$OP" == "all" ] || [ "$OP" == "old" ]
then
 all
 jar cvf $DIR/testvectors_v1rc.jar $OUT_DIR/*.json
else
 new
fi


stop=$(date +'%s')
echo "Elapsed: $(( stop - start )) sec"

