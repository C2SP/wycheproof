package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

type testVector struct {
	TcId    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	Iv      string   `json:"iv"`
	Aad     string   `json:"aad"`
	Msg     string   `json:"msg"`
	Ct      string   `json:"ct"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type testGroup struct {
	IvSize   int          `json:"ivSize"`
	KeySize  int          `json:"keySize"`
	TagSize  int          `json:"tagSize"`
	TestType string       `json:"type"`
	Tests    []testVector `json:"tests"`
}

type notes struct {
	ConstructedIv string `json:"ConstructedIv"`
	ZeroLengthIv  string `json:"ZeroLengthIv"`
}

type testsFile struct {
	Algorithm        string      `json:"algorithm"`
	GeneratorVersion string      `json:"generatorVersion"`
	Notes            notes       `json:"notes"`
	NumberOfTests    uint32      `json:"numberOfTests"`
	Header           []string    `json:"header"`
	TestGroups       []testGroup `json:"testGroups"`
}

type gcmTestVector struct {
	tcId              int
	pt                []byte
	aad               []byte
	ct                []byte
	ptHex             string
	ctHex             string
	parameters        []byte
	key               []byte
	nonceLengthInBits int
	tagLengthInBits   int
	result            string
}

var gcmTestVectors []gcmTestVector

var acceptable_values_slice = []string{"valid", "invalid", "acceptable"}

var acceptable_values map[string]struct{}

func sliceToMap(slice []string) map[string]struct{} {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	return set
}

func contains(set map[string]struct{}, item string) bool {
	_, ok := set[item]
	return ok
}

func init() {
	acceptable_values = sliceToMap(acceptable_values_slice)

	file, err := os.Open("testvectors/aes_gcm_test.json")
	if err != nil {
		panic(err.Error())
	}
	dec := json.NewDecoder(file)

	var tf testsFile
	err = dec.Decode(&tf)
	if err != nil {
		panic(err.Error())
	}
	for _, tg := range tf.TestGroups {
		for _, t := range tg.Tests {
			tv, err := newGcmTestVector(t.TcId, t.Msg, t.Key, t.Iv, t.Aad, t.Ct, t.Tag, t.Result)
			if err != nil {
				panic(err)
			}
			gcmTestVectors = append(gcmTestVectors, tv)
		}
	}
	if len(gcmTestVectors) == 0 {
		panic("No vectors")
	}

}

func newGcmTestVector(tcId int, message string, keyMaterial string, nonce string, aad string, ciphertext string, tag string, result string) (gcmTestVector, error) {
	pttest, err := hex.DecodeString(message)
	if err != nil {
		return gcmTestVector{}, err
	}
	aadtest, err := hex.DecodeString(aad)
	if err != nil {
		return gcmTestVector{}, err
	}
	cttest, err := hex.DecodeString(ciphertext + tag)
	if err != nil {
		return gcmTestVector{}, err
	}
	parametertest, err := hex.DecodeString(nonce)
	if err != nil {
		return gcmTestVector{}, err
	}
	tagLengthInBits := 4 * len(tag)
	nonceLengthInBits := 4 * len(nonce)
	keytest, err := hex.DecodeString(keyMaterial)
	if err != nil {
		return gcmTestVector{}, err
	}

	if !contains(acceptable_values, result) {
		return gcmTestVector{}, errors.New("Invalid result status.")
	}
	return gcmTestVector{tcId, pttest, aadtest, cttest, message, ciphertext + tag, parametertest, keytest, nonceLengthInBits, tagLengthInBits, result}, nil
}

func newGCMWrapper(test gcmTestVector, block cipher.Block) (cipher.AEAD, error) {
	switch {
	case test.tagLengthInBits != 128:
		return cipher.NewGCMWithTagSize(block, test.tagLengthInBits>>3)
	case test.nonceLengthInBits != 96:
		return cipher.NewGCMWithNonceSize(block, test.nonceLengthInBits>>3)
	}
	return cipher.NewGCM(block)
}

func TestVectorsRunner(t *testing.T) {
	t.Run("TestAllVectors", func(t *testing.T) { invokeTest(t, "TestAllVectors", testSingleVector) })
	t.Run("TestIVReuse", func(t *testing.T) { invokeTest(t, "TestIVReuse", testSingleIVReuse) })
	t.Run("TestByteBufferSize", func(t *testing.T) { invokeTest(t, "TestByteBufferSize", testSingleByteBufferSize) })
	t.Run("TestByteArrayTooShort", func(t *testing.T) { invokeTest(t, "TestByteArrayTooShort", testSingleByteArrayTooShort) })
}

func invokeTest(t *testing.T, testName string, testFunction func(gcmTestVector) (bool, string)) {
	failures := 0
	for _, test := range gcmTestVectors {
		res, msg := testFunction(test)
		if !res {
			failures += 1
		}
		if !res && testing.Verbose() {
			t.Logf(msg)
		}
	}
	if failures > 0 {
		t.Errorf("%s: %d / %d tests failed.", testName, failures, len(gcmTestVectors))
	}
}

func testSingleVector(test gcmTestVector) (result bool, msg string) {
	block, err := aes.NewCipher(test.key)
	if err != nil {
		return false, err.Error()
	}
	agcm, err := newGCMWrapper(test, block)
	if err != nil {
		return false, err.Error()
	}

	ct := agcm.Seal(nil, test.parameters, test.pt, test.aad)

	result = (bytes.Equal(ct, test.ct) && (test.result != "invalid")) || (!bytes.Equal(ct, test.ct) && (test.result == "invalid"))
	msg = fmt.Sprintf("Test %d: \n\tGot ciphertext : %x\n\tExpected       : %x\n\tResult         : %s\n\tIV             : %x\n\tNonce length   : %d\n\tTag length     : %d", test.tcId, ct, test.ct, test.result, test.parameters, test.nonceLengthInBits, test.tagLengthInBits)
	return
}

//cipher does not support the update operation, thus we cannot test encryption with empty arrays.
//cipher does not support the update operation, thus we cannot test decryption with empty arrays.
//cipher does not support the updateAAD operation, thus we cannot test late updates to the AAD.

func testSingleIVReuse(test gcmTestVector) (result bool, msg string) {
	defer func() {
		if r := recover(); r != nil {
			result = true
			msg = fmt.Sprintf("Test %d correctly panics.", test.tcId)
		}
	}()
	block, err := aes.NewCipher(test.key)
	if err != nil {
		return false, err.Error()
	}
	agcm, err := newGCMWrapper(test, block)
	if err != nil {
		return false, err.Error()
	}

	_ = agcm.Seal(nil, test.parameters, test.pt, test.aad)
	_ = agcm.Seal(nil, test.parameters, test.pt, test.aad)
	output := fmt.Sprintf("Fail %d: AES-GCM should not allow IV reuse.", test.tcId)
	return false, output
}

func testSingleByteBufferSize(test gcmTestVector) (result bool, msg string) {
	block, err := aes.NewCipher(test.key)
	if err != nil {
		return false, err.Error()
	}
	agcm, err := newGCMWrapper(test, block)
	if err != nil {
		return false, err.Error()
	}

	outputSize := agcm.Overhead() + len(test.pt)
	if len(test.ct) != outputSize {
		result = false
		msg = fmt.Sprintf("Fail %d: \n\tComputed length = %d\n\tExpected length = %d\n", test.tcId, len(test.ct), outputSize)
		return
	}
	return true, "Correct buffer size computed"
}

//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test byte buffers.
//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test byte buffer aliasing.

func TestLargeArrayAlias(t *testing.T) {
	failures := 0
	const ptLength = 8192
	ptVector := make([]byte, ptLength)
	_, err := rand.Read(ptVector)
	if err != nil {
		t.Errorf(err.Error())
	}
	for outputOffset := -32; outputOffset <= 32; outputOffset++ {
		func(outputOffset int) {
			defer func() {
				if r := recover(); r != nil {
					if r == "crypto/cipher: invalid buffer overlap" {
						if testing.Verbose() {
							t.Logf("Correctly panics when buffers overlap")
						}
					} else {
						t.Errorf("Failed with error %s.", r)
					}
				}
			}()
			block, err := aes.NewCipher(make([]byte, 16))
			if err != nil {
				t.Errorf(err.Error())
			}
			agcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Errorf(err.Error())
			}

			inputOffsetInBuffer := 32
			outputOffsetInBuffer := inputOffsetInBuffer + outputOffset
			sliceLength := agcm.Overhead() + ptLength

			inBuf := make([]byte, sliceLength+func(i, j int) int {
				if i > j {
					return i
				}
				return j
			}(inputOffsetInBuffer, outputOffsetInBuffer))
			outBuf := inBuf

			copy(inBuf[inputOffsetInBuffer:], ptVector[0:])

			ctLength := agcm.Overhead() + ptLength

			agcm.Seal(outBuf[:outputOffsetInBuffer], make([]byte, 12), inBuf[inputOffsetInBuffer:inputOffsetInBuffer+ptLength], nil)

			copy(inBuf[inputOffsetInBuffer:], outBuf[outputOffsetInBuffer:outputOffsetInBuffer+ctLength])

			_, err = agcm.Open(outBuf[:outputOffsetInBuffer], make([]byte, 12), inBuf[inputOffsetInBuffer:inputOffsetInBuffer+ctLength], nil)
			if err != nil {
				t.Errorf(err.Error())
			}
			if !bytes.Equal(outBuf[outputOffsetInBuffer:outputOffsetInBuffer+ptLength], ptVector) {
				failures += 1
				if testing.Verbose() {
					t.Logf("Large arrays are not copy safe:Offset   : %d\n\tPtVector : %x\n\tInBuf    : %x\n\tOutBuf   : %x", outputOffset, ptVector, inBuf, outBuf)
				}
			}
		}(outputOffset)
	}
	if failures > 0 {
		t.Errorf("%d / %d tests failed.", failures, len(gcmTestVectors))
	}
}

//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test byte buffer shift aliasing.

//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test the use of read only byte buffers.
//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test the use of byte buffers with offsets.
//cipher does not support the use of byte buffers for encryption or decryption, thus we cannot test the use of byte buffers that are too short. We test instead the behaviour when byte arrays are too short.

func testSingleByteArrayTooShort(test gcmTestVector) (result bool, msg string) {
	block, err := aes.NewCipher(test.key)
	if err != nil {
		return false, err.Error()
	}
	agcm, err := newGCMWrapper(test, block)
	if err != nil {
		return false, err.Error()
	}
	ctshort := make([]byte, len(test.ct)-1)
	ctshort = agcm.Seal(ctshort[:0], test.parameters, test.pt, test.aad)
	result = (bytes.Equal(ctshort, test.ct) && (test.result != "invalid")) || (!bytes.Equal(ctshort, test.ct) && (test.result == "invalid"))
	msg = fmt.Sprintf("Fail %d: \n\tGot ciphertext : %x\n\tExpected       : %x\n\tResult         : %s\n\tIV             : %x\n\tNonce length   : %d\n\tTag length     : %d", test.tcId, ctshort, test.ct, test.result, test.parameters, test.nonceLengthInBits, test.tagLengthInBits)
	return
}

//cipher does not support the update operation, thus we cannot test encryption with empty byte buffers.
//cipher does not support the update operation, thus we cannot test decryption with empty byte buffers.

func TestDefaultTagSizeIvParameterSpec(t *testing.T) {
	key := make([]byte, 16)
	input := make([]byte, 16)
	nonce := make([]byte, 12)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}
	agcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf(err.Error())
	}

	ct := agcm.Seal(nil, nonce, input, nil)
	if len(ct) != len(input)+16 {
		t.Errorf("Uses a default tag size other than 16 (%d).", len(ct)-len(input))
	}
}

//cipher does not provide an algorithm parameters generator, thus we cannot test it.

func TestWrappedAroundCounter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Failed with error %s.", r)
		}
	}()
	if testing.Short() {
		//This test uses a lot of memory. Skipping prevents the test from fatally crashing on low memory machines.
		t.Skip("Skipping wrap around counter test in short mode")
	}
	iv := make([]byte, 12)
	input_size := (4294967296 + 2) * 16
	input := make([]byte, input_size)
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Errorf(err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm.Seal(input[:0], iv, input[:input_size-16], nil)
	t.Errorf("Allows inputs of size %d.\n\tFirst byte : %x\n\tLast byte  : %x", input_size, input[0:10], input[input_size-11:input_size])
}

func TestEncryptEmptyPlaintextWithEmptyIV(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Correctly panicked with error %s.", r)
		}
	}()
	emptyIV := make([]byte, 0)
	input := make([]byte, 16)
	key, err := hex.DecodeString("56aae7bd5cbefc71d31c4338e6ddd6c5")
	if err != nil {
		t.Errorf(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf(err.Error())
	}
	//A block encrypted with an empty IV leaks the hash subkey.
	//If the encryption is allowed to succeed then the hashkey will equal the ciphertext.
	hashkey := make([]byte, 16)
	block.Encrypt(hashkey, input)
	_ = agcm.Seal(nil, emptyIV, input, nil)
	t.Errorf("AES-GCM must not accept an IV of size 0.")
}

func TestDecryptWithEmptyIV(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Correctly panicked with error %s.", r)
		}
	}()
	emptyIV := make([]byte, 0)
	key, err := hex.DecodeString("56aae7bd5cbefc71d31c4338e6ddd6c5")
	if err != nil {
		t.Errorf(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Errorf(err.Error())
	}

	ct, err := hex.DecodeString("2b65876c00d77facf8f3d0e5be792b129bab10b25bcb739b92d6e2eab241245ff449")
	if err != nil {
		t.Errorf(err.Error())
	}

	tag, err := hex.DecodeString("c2b2d7086e7fa84ca795a881b540")
	if err != nil {
		t.Errorf(err.Error())
	}

	_, _ = agcm.Open(nil, emptyIV, append(ct, tag...), nil)
	t.Errorf("AES-GCM must not accept an IV of size 0.")
}

func TestEncryptEmptyPlaintextWithEmptyIVForced(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Correctly panicked with error %s.", r)
		}
	}()
	emptyIV := make([]byte, 0)
	input := make([]byte, 16)
	key, err := hex.DecodeString("56aae7bd5cbefc71d31c4338e6ddd6c5")
	if err != nil {
		t.Errorf(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm, err := cipher.NewGCMWithNonceSize(block, 0)
	if err != nil {
		t.Errorf(err.Error())
	}

	//A block encrypted with an empty IV leaks the hash subkey.
	//If the encryption is allowed to succeed then the hashkey will equal the ciphertext.
	hashkey := make([]byte, 16)
	block.Encrypt(hashkey, input)
	_ = agcm.Seal(nil, emptyIV, input, nil)
	t.Errorf("AES-GCM must not accept an IV of size 0.")
}

func TestDecryptWithEmptyIVForced(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Correctly panicked with error %s.", r)
		}
	}()
	emptyIV := make([]byte, 0)
	key, err := hex.DecodeString("56aae7bd5cbefc71d31c4338e6ddd6c5")
	if err != nil {
		t.Errorf(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf(err.Error())
	}

	agcm, err := cipher.NewGCMWithNonceSize(block, 0)
	if err != nil {
		t.Errorf(err.Error())
	}

	ct, err := hex.DecodeString("2b65876c00d77facf8f3d0e5be792b129bab10b25bcb739b92d6e2eab241245ff449")
	if err != nil {
		t.Errorf(err.Error())
	}

	tag, err := hex.DecodeString("c2b2d7086e7fa84ca795a881b540")
	if err != nil {
		t.Errorf(err.Error())
	}

	_, _ = agcm.Open(nil, emptyIV, append(ct, tag...), nil)
	t.Errorf("AES-GCM must not accept an IV of size 0.")
}
