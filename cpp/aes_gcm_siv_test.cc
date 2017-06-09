// Copyright (c) 2017, Google Inc.

// The lastest version of AES-GCM-SIV is defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-04
//
// NOTE(bleichen): This test is for internal use only and has not been adapted
//   for release. I.e. it uses gunit instead of gtest and some google only
//   libraries such as "strings/escaping.h". The directory for the test vectors
//   "third_party/wycheproof/testvectors/" is hard coded, but this would
//   probably change if the tests were released.
//   OpenSSL (rsp. BoringSSL) are difficult to test because of an abundance of
//   interfaces. Verifying that these libraries are correct when using one
//   interface does not imply the correctness when using another interface.
//   Since it is easy to use these libraries incorrectly it is often better
//   to test an implementation through higher level interfaces.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <utility>

#include "strings/escaping.h"
#include "testing/base/public/gunit.h"

#include "third_party/jsoncpp/reader.h"
#include "third_party/openssl/aead.h"
#include "third_party/openssl/crypto.h"
#include "third_party/openssl/err.h"
#include "third_party/openssl/evp.h"

namespace wycheproof {

// Converts a JSON value into a byte array.
// Byte arrays are always hexadecimal representation.
static string getBytes(const Json::Value &val) {
  return strings::a2b_hex(val.asString());
}

static string HexEncode(const string& bytes) {
  return strings::b2a_hex(bytes);
}

static std::unique_ptr<Json::Value> ReadJsonFile(const string &filename) {
  const string kTestVectors = "third_party/wycheproof/testvectors/";
  std::ifstream input;
  input.open(kTestVectors + filename);
  std::unique_ptr<Json::Value> root(new Json::Value);
  input >> (*root);
  return root;
}


static const EVP_AEAD* GetCipherForKeySize(int size_in_bytes) {
  switch (size_in_bytes) {
    case 16 : return EVP_aead_aes_128_gcm_siv();
    case 32 : return EVP_aead_aes_256_gcm_siv();
    default : return nullptr;
  }
}

/**
 * Encrypt a ciphertext
 * Returns false if the encryption failed.
 */
bool Encrypt(
    const string& key,
    const string& pt,
    const string& iv,
    const string& aad,
    size_t tag_size,
    string *ciphertext) {
  const EVP_AEAD* aead = GetCipherForKeySize(key.size());

  bssl::ScopedEVP_AEAD_CTX ctx;
  if (1 != EVP_AEAD_CTX_init_with_direction(
               ctx.get(), aead,
               reinterpret_cast<const uint8_t *>(key.data()), key.size(),
               tag_size, evp_aead_seal)) {
    return false;
  }

  size_t ciphertext_size = pt.size() + tag_size;
  std::vector<uint8_t> ct(ciphertext_size);
  size_t written;
  int ret = EVP_AEAD_CTX_seal(
                ctx.get(), ct.data(), &written, ct.size(),
                reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
                reinterpret_cast<const uint8_t *>(pt.data()), pt.size(),
                reinterpret_cast<const uint8_t *>(aad.data()), aad.size());
  if (1 != ret) {
    return false;
  }
  *ciphertext = std::string(reinterpret_cast<const char*>(&ct[0]), written);
  return true;
}

bool Decrypt(
    const string& key,
    const string& ct,
    const string& iv,
    const string& aad,
    size_t tag_size,
    string *plaintext) {
  *plaintext = "";
  const EVP_AEAD* aead = GetCipherForKeySize(key.size());

  bssl::ScopedEVP_AEAD_CTX ctx;
  if (1 != EVP_AEAD_CTX_init_with_direction(
               ctx.get(), aead,
               reinterpret_cast<const uint8_t *>(key.data()), key.size(),
               tag_size, evp_aead_seal)) {
    return false;
  }

  std::vector<uint8_t> pt(ct.size());
  size_t written;
  int ret = EVP_AEAD_CTX_open(
                ctx.get(), pt.data(), &written, pt.size(),
                reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
                reinterpret_cast<const uint8_t *>(ct.data()), ct.size(),
                reinterpret_cast<const uint8_t *>(aad.data()), aad.size());
  if (1 != ret) {
    return false;
  }
  *plaintext = std::string(reinterpret_cast<const char*>(&pt[0]), written);
  return true;
}

static string GetError() {
  auto err = ERR_peek_last_error();
  string lib(ERR_lib_error_string(err));
  string func(ERR_func_error_string(err));
  string reason(ERR_reason_error_string(err));
  return lib + ":" + func + ":" + reason;
}

bool TestAesGcmSiv(const Json::Value &root) {
  VLOG(0) << root["algorithm"].asString();
  VLOG(0) << root["generatorVersion"].asString();
  int correct_encryptions = 0;
  int correct_decryptions = 0;
  for (const Json::Value& test_group : root["testGroups"]) {
    // AES-GCM-SIV generally uses 96-bit IVs.
    const size_t iv_size = test_group["ivSize"].asInt();
    // AES-GCM-SIV generally uses 128-bit IVs.
    const size_t tag_size = test_group["tagSize"].asInt();
    // AES-GCM-SIV uses either 128 or 256-bit keys.
    const size_t key_size = test_group["keySize"].asInt();
    for (const Json::Value& test : test_group["tests"]) {
      string comment = test["comment"].asString();
      string key = getBytes(test["key"]);
      string iv = getBytes(test["iv"]);
      string msg = getBytes(test["msg"]);
      string ct = getBytes(test["ct"]);
      string aad = getBytes(test["aad"]);
      string tag = getBytes(test["tag"]);
      string id = test["tcId"].asString();
      string expected = test["result"].asString();
      // TODO(bleichen): The value result does not encode enough information:
      //   We have to distinguish between test vectors where the parameters
      //   are invalid (i.e. where encryption should fail) and
      //   test vectors where the tag is incorrect (i.e. where
      //   encryption would return a different tag)
      string encrypted;
      bool success = Encrypt(key, msg, iv, aad, tag.size(), &encrypted);
      if (expected == "valid") {
        if (success) {
          if (encrypted == ct + tag) {
            ++correct_encryptions;
          } else {
            ADD_FAILURE()
                << "Incorrect encryption:" << id
                << " encrypted:" << HexEncode(encrypted)
                << " expected: " << HexEncode(ct + tag);
          }
        } else {
          // Some implementations reject some small parameters.
          // OpenSSL currently accepts all sizes.
          // If this ever changes then we might skip this failure.
          ADD_FAILURE()
              << "could not encrypt test with tcId:" << id
              << " iv_size:" << iv_size
              << " tag_size:" << tag_size
              << " key_size:" << key_size
              << " error:" << GetError();
        }
      } else {
        if (success) {
          if (encrypted == ct + tag) {
            // Most likely an encryption with invalid parameters such as
            // IV = "".
            ADD_FAILURE() << "encrypted with invalid parameters:" << id;
          } else {
            // Invalid test vectors are typically test vectors with an
            // incorrect ciphertext. Trying to reencrypt just gives the
            // correct ciphertext and does not detect the broken ciphertext.
            ++correct_encryptions;
          }
        } else {
          ++correct_encryptions;
        }
      }

      string decrypted;
      success = Decrypt(key, ct + tag, iv, aad, tag.size(), &decrypted);
      if (expected == "valid") {
        if (success) {
          if (msg == decrypted) {
            ++correct_decryptions;
          } else {
            ADD_FAILURE() << "Incorrect decryption:" << id;
          }
        } else {
          // Sometimes implementations reject small parameter sizes.
          // OpenSSL doesn't have such restrictions.
          // If this changes then this failure could be skipped.
          ADD_FAILURE()
              << "Could not decrypt test with tcId:" << id
              << " iv_size:" << iv_size
              << " tag_size:" << tag_size
              << " key_size:" << key_size
              << " error:" << GetError();
        }
      } else {
        if (success) {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
        } else {
          ++correct_decryptions;
        }
      }
    }
  }
  int num_tests = root["numberOfTests"].asInt();
  VLOG(0) << "total number of tests: " << num_tests;
  VLOG(0) << "correct encryptions:" << correct_encryptions;
  VLOG(0) << "correct decryptions:" << correct_decryptions;
  return (correct_encryptions == num_tests) &&
         (correct_decryptions == num_tests);
}

TEST(AesGcmSivTest, TestVectors) {
  std::unique_ptr<Json::Value> root = ReadJsonFile("aes_gcm_siv_test.json");
  ASSERT_TRUE(TestAesGcmSiv(*root));
}

}  // namespace wycheproof

