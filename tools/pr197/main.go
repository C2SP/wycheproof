package main

import (
	"bytes"
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	mlkem1024 "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	mlkem512 "github.com/cloudflare/circl/kem/mlkem/mlkem512"
	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

//go:generate go-jsonschema -p main -o schema.go ../../schemas/mlkem_test_schema.json

func main() {
	files := []string{
		"../../testvectors_v1/mlkem_512_decaps_seed_test.json",
		"../../testvectors_v1/mlkem_768_decaps_seed_test.json",
		"../../testvectors_v1/mlkem_1024_decaps_seed_test.json",
	}

	for _, inputPath := range files {
		processFile(inputPath)
	}
}

func processFile(inputPath string) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", inputPath, err)
	}

	var testData MlkemTestSchemaJson
	if err := json.Unmarshal(data, &testData); err != nil {
		log.Fatalf("failed to unmarshal %s: %v", inputPath, err)
	}

	var bitsize int
	if strings.Contains(inputPath, "512") {
		bitsize = 512
	} else if strings.Contains(inputPath, "768") {
		bitsize = 768
	} else if strings.Contains(inputPath, "1024") {
		bitsize = 1024
	} else {
		log.Fatalf("unknown bitsize in filename: %s", inputPath)
	}

	var outputLines []string
	for _, tg := range testData.TestGroups {
		tgBytes, err := json.Marshal(tg)
		if err != nil {
			log.Fatalf("failed to marshal test group: %v", err)
		}

		var testGroup MLKEMTestGroup
		if err := json.Unmarshal(tgBytes, &testGroup); err != nil {
			log.Fatalf("failed to unmarshal test group: %v", err)
		}

		for _, test := range testGroup.Tests {
			var ekLine string

			seedBytes, err := hex.DecodeString(test.Seed)
			if err == nil && len(seedBytes) == 64 {
				ekLine = generateEK(bitsize, seedBytes, test.TcId)
			}
			outputLines = append(outputLines, ekLine)
		}
	}

	base := filepath.Base(inputPath)
	outputPath := filepath.Join(filepath.Dir(inputPath), base[:len(base)-5]+".ek.txt")
	outputContent := strings.Join(outputLines, "\n") + "\n"

	if err := os.WriteFile(outputPath, []byte(outputContent), 0644); err != nil {
		log.Fatalf("failed to write %s: %v", outputPath, err)
	}

	log.Printf("successfully wrote %d lines to %s", len(outputLines), outputPath)
}

func generateEK(bitsize int, seedBytes []byte, tcId int) string {
	switch bitsize {
	case 512:
		// Only circl for 512
		circlPk, _ := mlkem512.NewKeyFromSeed(seedBytes)
		circlEkBytes, err := circlPk.MarshalBinary()
		if err != nil {
			log.Fatalf("circl MarshalBinary failed for tcId %d: %v", tcId, err)
		}
		return hex.EncodeToString(circlEkBytes)

	case 768:
		// Both stdlib and circl, verify match
		dk, err := mlkem.NewDecapsulationKey768(seedBytes)
		if err != nil {
			return ""
		}
		stdlibEkBytes := dk.EncapsulationKey().Bytes()

		circlPk, _ := mlkem768.NewKeyFromSeed(seedBytes)
		circlEkBytes, err := circlPk.MarshalBinary()
		if err != nil {
			log.Fatalf("circl MarshalBinary failed for tcId %d: %v", tcId, err)
		}

		if !bytes.Equal(stdlibEkBytes, circlEkBytes) {
			log.Fatalf("EK mismatch for tcId %d!\nstdlib: %x\ncircl:  %x",
				tcId, stdlibEkBytes, circlEkBytes)
		}
		return hex.EncodeToString(stdlibEkBytes)

	case 1024:
		// Both stdlib and circl, verify match
		dk, err := mlkem.NewDecapsulationKey1024(seedBytes)
		if err != nil {
			return ""
		}
		stdlibEkBytes := dk.EncapsulationKey().Bytes()

		circlPk, _ := mlkem1024.NewKeyFromSeed(seedBytes)
		circlEkBytes, err := circlPk.MarshalBinary()
		if err != nil {
			log.Fatalf("circl MarshalBinary failed for tcId %d: %v", tcId, err)
		}

		if !bytes.Equal(stdlibEkBytes, circlEkBytes) {
			log.Fatalf("EK mismatch for tcId %d!\nstdlib: %x\ncircl:  %x",
				tcId, stdlibEkBytes, circlEkBytes)
		}
		return hex.EncodeToString(stdlibEkBytes)

	default:
		log.Fatalf("unsupported bitsize: %d", bitsize)
		return ""
	}
}
