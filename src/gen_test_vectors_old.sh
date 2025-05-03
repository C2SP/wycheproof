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

# Test vector generation using Python 3.7.

# Parsing parameters
OPT=--release
while getopts ":adir" opt; do
  case ${opt} in
    a )
      OPT=--alpha
      echo "Including test vectors in alpha status"
      ;;
    i )
      OPT=--internal
      echo "Generating internal version of test vectors"
      ;;
    r )
      OPT=--release
      echo "Generating test vectors for release"
      ;;
    d )
      OPT=--dump
      echo "No test vectors are generated"
      ;;
    \? )
      echo "Invalid parameter"
      echo "Usage: gen_test_vectors [-adir]"
      echo "-a include test vectors in alpha state."
      echo "-r generate release version."
      echo "-i generete the internal version."
      echo "-d dump the generator calls with arguments."
      exit 1
      ;;
  esac
done

start=$(date +'%s')

# Python version.
#
# Unfortunately python changes a lot from version to version.
# Sometimes the test vector generation has to use multiple versions,
# so that all required features are available.
#
# The code for generating the test vectors does not attempt to
# be compatible with Python 2. It also does not attempt to be
# backwards compatible with old Python 3 versions. The major
# reasons are:
# - incompatibilities between Python 2 and Python 3 (e.g. str/bytes)
# - installed crypto libraries and hashlib differ between versions.
# - support for type hinting. Runtime checks for type hints use
#   code that depends on the version.
# The main requirement here is that it supports:
# - cryptography.hazmat
# - SHA-3
PYTHON=python3

if [ "$OPT" == "--internal" ] || [ "$OPT" == "--alpha" ]
then
  DIR=/google/src/cloud/bleichen/keymaster1/google3/third_party/wycheproof/internal
  OUT_DIR=$DIR/testvectors
  rm $OUT_DIR/*_test.json
elif [ "$OPT" == "--release" ]
then
  DIR=/google/src/cloud/bleichen/keymaster1/google3/experimental/users/bleichen/wycheproof
  OUT_DIR=$DIR/testvectors
  rm $OUT_DIR/*_test.json
fi

$PYTHON gen_primetest.py $OPT --out=$OUT_DIR/primality_test.json &

# usage gen <generator> <file>
gen() {
  $PYTHON gen_$1.py $OPT --out=$OUT_DIR/$2_test.json &
}

# Test vectors for symmetric algorithms
gen aes_gcm aes_gcm
gen aes_gcm_siv aes_gcm_siv
gen aes_eax aes_eax
gen aes_ccm aes_ccm
gen chacha_poly1305 chacha20_poly1305
gen xchacha_poly1305 xchacha20_poly1305
gen aes_siv_aead aead_aes_siv_cmac
gen aes_siv aes_siv_cmac
gen aes_cbc_pkcs5 aes_cbc_pkcs5
gen aegis128 aegis128
gen aegis128L aegis128L
gen aegis256 aegis256
gen kw kw
gen kwp kwp

# Test vectors for randomized MACS
$PYTHON gen_vmac.py $OPT --tag_sizes=64 --out=$OUT_DIR/vmac_64_test.json &
$PYTHON gen_vmac.py $OPT --tag_sizes=128 --out=$OUT_DIR/vmac_128_test.json &
$PYTHON gen_gmac.py $OPT --tag_sizes=128 --invalid_sizes --out=$OUT_DIR/gmac_test.json &

# Test vectors for MACs
gen aes_cmac aes_cmac

# gen_hmac sha file
gen_hmac() {
  $PYTHON gen_hmac.py $OPT --sha=$1 --out=$OUT_DIR/$2_test.json
}
gen_hmac "SHA-1" hmac_sha1
gen_hmac "SHA-224" hmac_sha224
gen_hmac "SHA-256" hmac_sha256
gen_hmac "SHA-384" hmac_sha384
gen_hmac "SHA-512" hmac_sha512
gen_hmac "SHA3-224" hmac_sha3_224
gen_hmac "SHA3-256" hmac_sha3_256
gen_hmac "SHA3-384" hmac_sha3_384
gen_hmac "SHA3-512" hmac_sha3_512
gen_hmac "SHA-512/224" hmac_sha512_224
gen_hmac "SHA-512/256" hmac_sha512_256

# gen_hkdf sha file
gen_hkdf() {
  $PYTHON gen_hkdf.py $OPT --sha=$1 --out=$OUT_DIR/$2_test.json
}

gen_hkdf "SHA-1" hkdf_sha1
gen_hkdf "SHA-256" hkdf_sha256
gen_hkdf "SHA-384" hkdf_sha384
gen_hkdf "SHA-512" hkdf_sha512

$PYTHON gen_sip_hash.py $OPT --alg="SipHash24" --out=$OUT_DIR/siphash24_test.json
$PYTHON gen_sip_hash.py $OPT --alg="SipHashX24" --out=$OUT_DIR/siphashx24_test.json
wait

gen_rsapkcs1() {
  $PYTHON gen_rsaes_pkcs1.py $OPT --size=$1 --out=$OUT_DIR/$2_test.json &
}

gen_rsapkcs1 2048 rsa_pkcs1_2048
gen_rsapkcs1 3072 rsa_pkcs1_3072
gen_rsapkcs1 4096 rsa_pkcs1_4096

# Test vectors for RSA-OAEP
# gen_rsaoaep bitsize sha mgf file
gen_rsaoaep() {
  $PYTHON gen_rsa_oaep.py $OPT --size=$1 --sha=$2 --mgf=$3 --mgf_sha=$4 \
      --out=$OUT_DIR/$5_test.json &
}

gen_rsaoaep_three_primes() {
  $PYTHON gen_rsa_oaep.py $OPT --size=$1 --sha=$2 --mgf=$3 --mgf_sha=$4 \
      --out=$OUT_DIR/$5_test.json &
}

# mgf_sha = sha (default for BouncyCastle)
gen_rsaoaep 2048 "SHA-1" "MGF1" "SHA-1" rsa_oaep_2048_sha1_mgf1sha1
gen_rsaoaep 2048 "SHA-224" "MGF1" "SHA-224" rsa_oaep_2048_sha224_mgf1sha224
gen_rsaoaep 2048 "SHA-256" "MGF1" "SHA-256" rsa_oaep_2048_sha256_mgf1sha256
gen_rsaoaep 2048 "SHA-384" "MGF1" "SHA-384" rsa_oaep_2048_sha384_mgf1sha384
gen_rsaoaep 2048 "SHA-512" "MGF1" "SHA-512" rsa_oaep_2048_sha512_mgf1sha512
gen_rsaoaep 3072 "SHA-256" "MGF1" "SHA-256" rsa_oaep_3072_sha256_mgf1sha256
gen_rsaoaep 3072 "SHA-512" "MGF1" "SHA-512" rsa_oaep_3072_sha512_mgf1sha512
gen_rsaoaep 4096 "SHA-256" "MGF1" "SHA-256" rsa_oaep_4096_sha256_mgf1sha256
gen_rsaoaep 4096 "SHA-512" "MGF1" "SHA-512" rsa_oaep_4096_sha512_mgf1sha512

# Truncated hashes. Defined in RFC 8017, but not terribly useful.
# gen_rsaoaep 2048 "SHA-512/224" "MGF1" "SHA-512/224" rsa_oaep_2048_sha512_224_mgf1sha512_224
# gen_rsaoaep 2048 "SHA-512/256" "MGF1" "SHA-512/256" rsa_oaep_2048_sha512_256_mgf1sha512_256

# mgf = mgfsha1 (default for the SUN provider)
gen_rsaoaep 2048 "SHA-224" "MGF1" "SHA-1" rsa_oaep_2048_sha224_mgf1sha1
gen_rsaoaep 2048 "SHA-256" "MGF1" "SHA-1" rsa_oaep_2048_sha256_mgf1sha1
gen_rsaoaep 2048 "SHA-384" "MGF1" "SHA-1" rsa_oaep_2048_sha384_mgf1sha1
gen_rsaoaep 2048 "SHA-512" "MGF1" "SHA-1" rsa_oaep_2048_sha512_mgf1sha1
gen_rsaoaep 3072 "SHA-256" "MGF1" "SHA-1" rsa_oaep_3072_sha256_mgf1sha1
gen_rsaoaep 3072 "SHA-512" "MGF1" "SHA-1" rsa_oaep_3072_sha512_mgf1sha1
gen_rsaoaep 4096 "SHA-256" "MGF1" "SHA-1" rsa_oaep_4096_sha256_mgf1sha1
gen_rsaoaep 4096 "SHA-512" "MGF1" "SHA-1" rsa_oaep_4096_sha512_mgf1sha1

gen_rsaoaep_three_primes 2048 "SHA-1" "MGF1" "SHA-1" rsa_three_primes_oaep_2048_sha1_mgf1sha1
gen_rsaoaep_three_primes 3072 "SHA-224" "MGF1" "SHA-224" rsa_three_primes_oaep_3072_sha224_mgf1sha224
gen_rsaoaep_three_primes 2048 "SHA-256" "MGF1" "SHA-256" rsa_three_primes_oaep_4096_sha256_mgf1sha256

wait

# misc
$PYTHON gen_rsa_oaep.py $OPT --mode=misc --out=$OUT_DIR/rsa_oaep_misc_test.json &

# Test vectors for RSA-PSS
# gen_rsapss bitsize sha mgf slen
gen_rsapss() {
  $PYTHON gen_rsa_pss.py $OPT --size=$1 --sha=$2 --mgf=$3 --mgf_sha=$4 \
     --slen=$5 --out=$OUT_DIR/$6_test.json &
}

gen_rsapss 2048 "SHA-256" "MGF1" "SHA-256" 32 rsa_pss_2048_sha256_mgf1_32
gen_rsapss 3072 "SHA-256" "MGF1" "SHA-256" 32 rsa_pss_3072_sha256_mgf1_32
gen_rsapss 4096 "SHA-256" "MGF1" "SHA-256" 32 rsa_pss_4096_sha256_mgf1_32
gen_rsapss 4096 "SHA-512" "MGF1" "SHA-512" 32 rsa_pss_4096_sha512_mgf1_32
gen_rsapss 2048 "SHA-256" "MGF1" "SHA-256" 0 rsa_pss_2048_sha256_mgf1_0
gen_rsapss 2048 "SHA-1" "MGF1" "SHA-1" 20 rsa_pss_2048_sha1_mgf1_20
gen_rsapss 2048 "SHA-512/224" "MGF1" "SHA-512/224" 28 rsa_pss_2048_sha512_224_mgf1_28
gen_rsapss 2048 "SHA-512/256" "MGF1" "SHA-512/256" 32 rsa_pss_2048_sha512_256_mgf1_32

# Test vectors for RSA-PSS where hash functions are different
gen_rsapss 2048 "SHA-256" "MGF1" "SHA-1" 20 rsa_pss_2048_sha256_mgf1sha1_20


# Generate RSA-PSS testvectors that include the pkcs1Algorithm with MGF
# parameters.
$PYTHON gen_rsa_pss.py $OPT --size=2048 --sha="SHA-256" --mgf="MGF1" \
    --mgf_sha="SHA-256" --slen=32 --specify_pkcs1algorithm \
    --out=$OUT_DIR/rsa_pss_2048_sha256_mgf1_32_params_test.json &

# Generate RSA-PSS testvectors for just one message but combinations of hash
# functions and salt lengths.
$PYTHON gen_rsa_pss_misc.py $OPT --message="123400" \
    --out=$OUT_DIR/rsa_pss_misc_test.json &
$PYTHON gen_rsa_pss_misc.py $OPT --message="123400" \
    --specify_pkcs1algorithm \
    --out=$OUT_DIR/rsa_pss_misc_params_test.json &

# Test vectors for ECDH
gen_ecdh() {
  if [ "$1" == "" ]
  then
    $PYTHON gen_ecdh.py $OPT --deprecated=" use curve specific files instead" --out=$OUT_DIR/ecdh_test.json &
  else
    $PYTHON gen_ecdh.py $OPT --curve=$1 --out=$OUT_DIR/ecdh_$1_test.json &
  fi
}

gen_ecdh ""
gen_ecdh "secp224r1"
gen_ecdh "secp256r1"
gen_ecdh "secp256k1"
gen_ecdh "secp384r1"
gen_ecdh "secp521r1"
gen_ecdh "brainpoolP224r1"
gen_ecdh "brainpoolP256r1"
gen_ecdh "brainpoolP320r1"
gen_ecdh "brainpoolP384r1"
gen_ecdh "brainpoolP512r1"

wait

# Test vectors for ECDH with a specified encoding of the public key.
gen_ecdh_enc() {
  if [ "$1" == "" ]
  then
    $PYTHON gen_ecdh.py $OPT --encoding=$2 --deprecated="use curve specific files instead" --out=$OUT_DIR/ecdh_$2_test.json &
  else
    $PYTHON gen_ecdh.py $OPT --encoding=$2 --curve=$1 \
        --out=$OUT_DIR/ecdh_$1_$2_test.json &
  fi
}

# Test vectors for ECDH where both public and private keys are PEM encoded.
gen_ecdh_enc "secp224r1" "pem"
gen_ecdh_enc "secp256r1" "pem"
gen_ecdh_enc "secp384r1" "pem"
gen_ecdh_enc "secp521r1" "pem"


# Test vectors for ECDH where the public key is just an encoded point.
gen_ecdh_enc "secp224r1" "ecpoint"
gen_ecdh_enc "secp256r1" "ecpoint"
gen_ecdh_enc "secp384r1" "ecpoint"
gen_ecdh_enc "secp521r1" "ecpoint"

# TODO: deprecate the full file.
gen_ecdh_enc "" "webcrypto"
gen_ecdh_enc "secp256r1" "webcrypto"
gen_ecdh_enc "secp384r1" "webcrypto"
gen_ecdh_enc "secp521r1" "webcrypto"
gen_ecdh_enc "secp256k1" "webcrypto"

# Test vectors for AMD SEV
if [ "$OPT" == "--alpha" ] || [ "$OPT" == "--dump" ]
then
  gen_ecdh_enc "secp256r1" "amd_sev"
  gen_ecdh_enc "secp384r1" "amd_sev"
  gen_ecdh_enc "secp256k1" "amd_sev"
fi

# Test vectors for ECDSA verification
gen_ecdsa_old() {
  $PYTHON gen_ecdsa.py $OPT --curve="" --asnparsing=der --sha="" --deprecated="use curve specific files instead" --out=$OUT_DIR/$1_test.json &
}

gen_ecdsa() {
  $PYTHON gen_ecdsa.py $OPT --curve=$1 --asnparsing=der --sha=$2 --out=$OUT_DIR/$3_test.json &
}

gen_ecdsa_p1363() {
  $PYTHON gen_ecdsa.py $OPT --curve=$1 --encoding=p1363 --sha=$2 --out=$OUT_DIR/$3_test.json &
}

gen_ecdsa_bitcoin() {
  $PYTHON gen_ecdsa.py $OPT --curve=$1 --encoding=bitcoin --sha=$2 --out=$OUT_DIR/$3_test.json &
}

gen_ecdsa_amd_sev() {
  $PYTHON gen_ecdsa.py $OPT --curve=$1 --encoding=amd_sev --sha=$2 --out=$OUT_DIR/$3_test.json &
}

gen_ecdsa_old "ecdsa"
gen_ecdsa "secp224r1" "SHA-224" "ecdsa_secp224r1_sha224"
gen_ecdsa "secp224r1" "SHA-256" "ecdsa_secp224r1_sha256"
gen_ecdsa "secp224k1" "SHA-224" "ecdsa_secp224k1_sha224"
gen_ecdsa "secp224k1" "SHA-256" "ecdsa_secp224k1_sha256"
gen_ecdsa "secp224r1" "SHA-512" "ecdsa_secp224r1_sha512"
gen_ecdsa "secp256r1" "SHA-256" "ecdsa_secp256r1_sha256"
gen_ecdsa "secp256r1" "SHA-512" "ecdsa_secp256r1_sha512"
gen_ecdsa "secp256k1" "SHA-256" "ecdsa_secp256k1_sha256"
gen_ecdsa "secp256k1" "SHA-512" "ecdsa_secp256k1_sha512"
gen_ecdsa "secp384r1" "SHA-384" "ecdsa_secp384r1_sha384"
gen_ecdsa "secp384r1" "SHA-512" "ecdsa_secp384r1_sha512"
gen_ecdsa "secp521r1" "SHA-512" "ecdsa_secp521r1_sha512"
gen_ecdsa "brainpoolP224r1" "SHA-224" "ecdsa_brainpoolP224r1_sha224"
gen_ecdsa "brainpoolP256r1" "SHA-256" "ecdsa_brainpoolP256r1_sha256"
gen_ecdsa "brainpoolP320r1" "SHA-384" "ecdsa_brainpoolP320r1_sha384"
gen_ecdsa "brainpoolP384r1" "SHA-384" "ecdsa_brainpoolP384r1_sha384"
gen_ecdsa "brainpoolP512r1" "SHA-512" "ecdsa_brainpoolP512r1_sha512"

gen_ecdsa_p1363 "secp224r1" "SHA-224" "ecdsa_secp224r1_sha224_p1363"
gen_ecdsa_p1363 "secp224r1" "SHA-256" "ecdsa_secp224r1_sha256_p1363"
gen_ecdsa_p1363 "secp224r1" "SHA-512" "ecdsa_secp224r1_sha512_p1363"
gen_ecdsa_p1363 "secp224k1" "SHA-224" "ecdsa_secp224k1_sha224_p1363"
gen_ecdsa_p1363 "secp224k1" "SHA-256" "ecdsa_secp224k1_sha256_p1363"
gen_ecdsa_p1363 "secp256r1" "SHA-256" "ecdsa_secp256r1_sha256_p1363"
gen_ecdsa_p1363 "secp256r1" "SHA-512" "ecdsa_secp256r1_sha512_p1363"
gen_ecdsa_p1363 "secp256k1" "SHA-256" "ecdsa_secp256k1_sha256_p1363"
gen_ecdsa_p1363 "secp256k1" "SHA-512" "ecdsa_secp256k1_sha512_p1363"
gen_ecdsa_p1363 "secp384r1" "SHA-384" "ecdsa_secp384r1_sha384_p1363"
gen_ecdsa_p1363 "secp384r1" "SHA-512" "ecdsa_secp384r1_sha512_p1363"
gen_ecdsa_p1363 "secp521r1" "SHA-512" "ecdsa_secp521r1_sha512_p1363"
gen_ecdsa_p1363 "brainpoolP224r1" "SHA-224" "ecdsa_brainpoolP224r1_sha224_p1363"
gen_ecdsa_p1363 "brainpoolP256r1" "SHA-256" "ecdsa_brainpoolP256r1_sha256_p1363"
gen_ecdsa_p1363 "brainpoolP320r1" "SHA-384" "ecdsa_brainpoolP320r1_sha384_p1363"
gen_ecdsa_p1363 "brainpoolP384r1" "SHA-384" "ecdsa_brainpoolP384r1_sha384_p1363"
gen_ecdsa_p1363 "brainpoolP512r1" "SHA-512" "ecdsa_brainpoolP512r1_sha512_p1363"

gen_ecdsa_bitcoin "secp256k1" "SHA-256" "ecdsa_secp256k1_sha256_bitcoin"

if [ "$OPT" == "--alpha" ] || [ "$OPT" == "--dump" ]
then
  gen_ecdsa_amd_sev "secp256r1" "SHA-256" "ecdsa_secp256r1_sha256_amd_sev"
  gen_ecdsa_amd_sev "secp384r1" "SHA-384" "ecdsa_secp384r1_sha384_amd_sev"
  gen_ecdsa_amd_sev "secp256k1" "SHA-256" "ecdsa_secp256k1_sha256_amd_sev"
fi

# Generate some file using SHA-3
gen_ecdsa "secp224r1" "SHA3-224" "ecdsa_secp224r1_sha3_224"
gen_ecdsa "secp224r1" "SHA3-256" "ecdsa_secp224r1_sha3_256"
gen_ecdsa "secp224r1" "SHA3-512" "ecdsa_secp224r1_sha3_512"
gen_ecdsa "secp256r1" "SHA3-256" "ecdsa_secp256r1_sha3_256"
gen_ecdsa "secp256r1" "SHA3-512" "ecdsa_secp256r1_sha3_512"
gen_ecdsa "secp256k1" "SHA3-256" "ecdsa_secp256k1_sha3_256"
gen_ecdsa "secp256k1" "SHA3-512" "ecdsa_secp256k1_sha3_512"
gen_ecdsa "secp384r1" "SHA3-384" "ecdsa_secp384r1_sha3_384"
gen_ecdsa "secp384r1" "SHA3-512" "ecdsa_secp384r1_sha3_512"
gen_ecdsa "secp521r1" "SHA3-512" "ecdsa_secp521r1_sha3_512"
gen_ecdsa "brainpoolP224r1" "SHA3-224" "ecdsa_brainpoolP224r1_sha3_224"
gen_ecdsa "brainpoolP256r1" "SHA3-256" "ecdsa_brainpoolP256r1_sha3_256"
gen_ecdsa "brainpoolP320r1" "SHA3-384" "ecdsa_brainpoolP320r1_sha3_384"
gen_ecdsa "brainpoolP384r1" "SHA3-384" "ecdsa_brainpoolP384r1_sha3_384"
gen_ecdsa "brainpoolP512r1" "SHA3-512" "ecdsa_brainpoolP512r1_sha3_512"

wait

# Modified public keys
gen_eckey() {
  $PYTHON gen_eckey.py $OPT --encoding=$1 --out=$OUT_DIR/$2_test.json &
}

gen_eckey asn eckey
gen_eckey pem eckey_pem


# Generates invalid public keys.
gen rsa rsa

# Generates invalid private keys.
gen_rsa_priv_key() {
  $PYTHON gen_rsa_priv_key.py $OPT --size=$1 --encoding=$2 --out=$OUT_DIR/$3_test.json &
}

gen_rsa_three_prime_priv_key() {
  $PYTHON gen_rsa_priv_key.py $OPT --size=$1 --encoding=$2 --three_primes --out=$OUT_DIR/$3_test.json &
}

if [ "$OPT" == "--alpha" ] || [ "$OPT" == "--dump" ]
then
  gen_rsa_priv_key 2048 "asn" "rsa_private_key_pkcs8_2048"
  gen_rsa_priv_key 3072 "asn" "rsa_private_key_pkcs8_3072"
  gen_rsa_priv_key 4096 "asn" "rsa_private_key_pkcs8_4096"
  gen_rsa_priv_key 2048 "pem" "rsa_private_key_pem_2048"
  gen_rsa_priv_key 3072 "pem" "rsa_private_key_pem_3072"
  gen_rsa_priv_key 4096 "pem" "rsa_private_key_pem_4096"

  gen_rsa_three_prime_priv_key 2048 "asn" "rsa_three_prime_private_key_pkcs8_2048"
  gen_rsa_three_prime_priv_key 3072 "asn" "rsa_three_prime_private_key_pkcs8_3072"
  gen_rsa_three_prime_priv_key 2048 "pem" "rsa_three_prime_private_key_pem_2048"
  gen_rsa_three_prime_priv_key 3072 "pem" "rsa_three_prime_private_key_pem_3072"
fi


# Test vectors for RSA signature verification
gen_rsa_signatures() {
  $PYTHON gen_rsa_signature.py $OPT --op=verify --size=$1 --sha=$2 --out=$OUT_DIR/$3_test.json &
}

gen_rsa_signatures 0 "" "rsa_signature"
gen_rsa_signatures 2048 "SHA-224" "rsa_signature_2048_sha224"
gen_rsa_signatures 2048 "SHA-256" "rsa_signature_2048_sha256"
gen_rsa_signatures 2048 "SHA-384" "rsa_signature_2048_sha384"
gen_rsa_signatures 2048 "SHA-512" "rsa_signature_2048_sha512"
gen_rsa_signatures 3072 "SHA-256" "rsa_signature_3072_sha256"
gen_rsa_signatures 3072 "SHA-384" "rsa_signature_3072_sha384"
gen_rsa_signatures 3072 "SHA-512" "rsa_signature_3072_sha512"
gen_rsa_signatures 4096 "SHA-256" "rsa_signature_4096_sha256"
gen_rsa_signatures 4096 "SHA-384" "rsa_signature_4096_sha384"
gen_rsa_signatures 4096 "SHA-512" "rsa_signature_4096_sha512"
gen_rsa_signatures 2048 "SHA3-224" "rsa_signature_2048_sha3_224"
gen_rsa_signatures 2048 "SHA3-256" "rsa_signature_2048_sha3_256"
gen_rsa_signatures 2048 "SHA3-384" "rsa_signature_2048_sha3_384"
gen_rsa_signatures 2048 "SHA3-512" "rsa_signature_2048_sha3_512"
gen_rsa_signatures 3072 "SHA3-256" "rsa_signature_3072_sha3_256"
gen_rsa_signatures 3072 "SHA3-384" "rsa_signature_3072_sha3_384"
gen_rsa_signatures 3072 "SHA3-512" "rsa_signature_3072_sha3_512"
gen_rsa_signatures 2048 "SHA-512/224" "rsa_signature_2048_sha512_224"
gen_rsa_signatures 2048 "SHA-512/256" "rsa_signature_2048_sha512_256"
gen_rsa_signatures 3072 "SHA-512/256" "rsa_signature_3072_sha512_256"
gen_rsa_signatures 4096 "SHA-512/256" "rsa_signature_4096_sha512_256"
gen_rsa_signatures 8192 "SHA-256" "rsa_signature_8192_sha256"
gen_rsa_signatures 8192 "SHA-384" "rsa_signature_8192_sha384"
gen_rsa_signatures 8192 "SHA-512" "rsa_signature_8192_sha512"


# Test vectors for RSA signature verification
$PYTHON gen_rsa_signature.py $OPT --op=sign --out=$OUT_DIR/rsa_sig_gen_misc_test.json &
$PYTHON gen_rsa_signature.py $OPT --op=sign --three_primes \
  --out=$OUT_DIR/rsa_sig_gen_misc_three_primes_test.json &

# Test vectors for DSA verification
# $1 size p
# $2 size q
# $3 SHA
# $4 file
gen_dsa() {
  $PYTHON gen_dsa.py $OPT --sizep=$1 --sizeq=$2 --sha=$3 --out=$OUT_DIR/$4_test.json &
}

gen_dsa_p1363() {
  $PYTHON gen_dsa.py $OPT --sizep=$1 --sizeq=$2 --sha=$3 --encoding=p1363 --out=$OUT_DIR/$4_p1363_test.json &
}

gen_dsa 2048 224 "SHA-224" "dsa_2048_224_sha224"
gen_dsa 2048 224 "SHA-256" "dsa_2048_224_sha256"
gen_dsa 2048 256 "SHA-256" "dsa_2048_256_sha256"
gen_dsa 3072 256 "SHA-256" "dsa_3072_256_sha256"
gen_dsa_p1363 2048 224 "SHA-224" "dsa_2048_224_sha224"
gen_dsa_p1363 2048 224 "SHA-256" "dsa_2048_224_sha256"
gen_dsa_p1363 2048 256 "SHA-256" "dsa_2048_256_sha256"
gen_dsa_p1363 3072 256 "SHA-256" "dsa_3072_256_sha256"

# Old file: contains 1024 bit keys
$PYTHON gen_dsa.py $OPT --deprecated="use files with keysize and hash" --out=$OUT_DIR/dsa_test.json &

# Test vectors for ECNR verification
if [ "$OPT" == "--alpha" ] || [ "$OPT" == "--dump" ]
then
  gen ecnr ecnr
fi

# Test vectors for EDDSA
# $1 the algorithm (ed25519, ed448)
# $2 the file name
gen_eddsa() {
  $PYTHON gen_eddsa.py $OPT --alg=$1 --out=$OUT_DIR/$2.json &
}

gen_eddsa ed25519 eddsa_test
gen_eddsa ed448 ed448_test 

# Test vectors for XDH
# Parameters:
# $1 the encoding:
#    raw = public and private key are raw bytes
#    asn = public key is X.509 encoded, private key is PKCS #8 encoded (what jdk does)
# $2 the algorithm (x25519 or x448)
# $3 the middle part of the test vector file name.
gen_xdh() {
  $PYTHON gen_xdh.py $OPT --encoding=$1 --alg=$2 --out=$OUT_DIR/$3_test.json &
}

gen_xdh raw "x25519" "x25519"
gen_xdh asn "x25519" "x25519_asn"
gen_xdh jwk "x25519" "x25519_jwk"
gen_xdh pem "x25519" "x25519_pem"
gen_xdh raw "x448" "x448"
gen_xdh asn "x448" "x448_asn"
gen_xdh jwk "x448" "x448_jwk"
gen_xdh pem "x448" "x448_pem"

gen ecdsa_webcrypto ecdsa_webcrypto

wait

# ===== PKCS #11 =====

# Parameters
# $1 the size of the RSA key in bits
# $2 hash for OAEP (e.g. "SHA-1")
# $3 mgf (i.e. "MGF1")
# $4 hash for mgf (e.g. "SHA-1")
# $5 parameter description used in the file name
gen_ckm_rsa_aes_key_wrap() {
  $PYTHON gen_ckm_rsa_aes_key_wrap.py $OPT --size=$1 --sha=$2 --mgf=$3\
     --mgf_sha=$4 --out=$OUT_DIR/ckm_rsa_aes_key_wrap_$5_test.json &
}

if [ "$OPT" == "--alpha" ] || [ "$OPT" == "--dump" ]
then
  gen_ckm_rsa_aes_key_wrap 2048 "SHA-1" "MGF1" "SHA-1" 2048_mgf1_sha1
  gen_ckm_rsa_aes_key_wrap 2048 "SHA-256" "MGF1" "SHA-256" 2048_mgf1_sha256
  gen_ckm_rsa_aes_key_wrap 2048 "SHA-512" "MGF1" "SHA-512" 2048_mgf1_sha512
  gen_ckm_rsa_aes_key_wrap 3072 "SHA-1" "MGF1" "SHA-1" 3072_mgf1_sha1
  gen_ckm_rsa_aes_key_wrap 3072 "SHA-256" "MGF1" "SHA-256" 3072_mgf1_sha256
  gen_ckm_rsa_aes_key_wrap 3072 "SHA-512" "MGF1" "SHA-512" 3072_mgf1_sha512
  gen_ckm_rsa_aes_key_wrap 4096 "SHA-1" "MGF1" "SHA-1" 4096_mgf1_sha1
  gen_ckm_rsa_aes_key_wrap 4096 "SHA-256" "MGF1" "SHA-256" 4096_mgf1_sha256
  gen_ckm_rsa_aes_key_wrap 4096 "SHA-512" "MGF1" "SHA-512" 4096_mgf1_sha512
fi

# Make a jar using these options:
# c create a jar
# v verbose
# f make a file
wait
cd $DIR

if [ "$OPT" == "--alpha" ]
then
  jar cvf testvectors_alpha.jar $OUTDIR/*.json
elif [ "$OPT" == "--internal" ]
then
  jar cvf testvectors_internal.jar $OUTDIR/*.json
elif [ "$OPT" == "--release" ]
then
  jar cvf testvectors.jar $OUTDIR/*.json
fi

stop=$(date +'%s')
echo "Elapsed: $(( stop - start )) sec"

