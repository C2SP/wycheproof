// vectorlint analyzes vector files to flag potential issues
package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	schemaDirectory    = flag.String("schemas-dir", "schemas", "directory containing schema files")
	vectorsDirectories = flag.String("vectors-dir", "testvectors_v1,testvectors", "comma separated directories containing vector files")
	vectorFilter       = flag.String("vector-filter", "", "only validate vector files matching the provided pattern")
	vectorRegex        *regexp.Regexp
)

func main() {

	flag.Parse()

	vectorDirectoryParts := strings.Split(*vectorsDirectories, ",")

	log.Printf("reading schemas from %q\n", *schemaDirectory)
	log.Printf("reading vectors from %q\n", vectorDirectoryParts)

	if *vectorFilter != "" {
		vectorRegex = regexp.MustCompile(*vectorFilter)
		log.Printf("filtering vectors with %q\n", *vectorFilter)
	}

	schemaCompiler := jsonschema.NewCompiler()

	for _, f := range customFormats {
		schemaCompiler.RegisterFormat(&f)
	}
	schemaCompiler.AssertFormat() // Opt in to format validation.

	var results schemaLintResults

	for _, vectorDir := range vectorDirectoryParts {
		if err := lintVectorDir(schemaCompiler, &results, vectorDir); err != nil {
			log.Fatalf("error linting schemas: %v\n", err)
		}
	}

	log.Printf("linted %d vector files\n", results.total)
	log.Printf("valid: %d\n", results.valid)
	log.Printf("invalid: %d\n", results.invalid)
	log.Printf("no schema: %d\n", results.noSchema)
	log.Printf("ignored: %d\n", results.ignored)

	os.Exit(results.invalid)
}

var (
	// TODO(XXX): some _v1 vectors reference schema files that don't exist. Until fixed, ignore these schemas.
	missingSchemas = map[string]bool{
		// testvectors_v1/aes_ff1_base*_test.json:
		"fpe_str_test_schema.json": true,

		// testvectors_v1/aes_ff1_radix*_test.json:
		"fpe_list_test_schema.json": true,

		// testvectors_v1/ec_prime_order_curves_test.json:
		"ec_curve_test_schema.json": true,

		// testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json
		"ecdsa_bitcoin_verify_schema.json": true,

		// testvectors_v1/pbes2_hmacsha*_aes_*_test.json:
		"pbe_test_schema.json": true,

		// testvectors_v1/pbkdf2_hmacsha*_test.json:
		"pbkdf_test_schema.json": true,

		// testvectors_v1/rsa_pss_*_sha*_mgf*_params_test.json
		// testvectors_v1/rsa_pss_misc_params_test.json:
		"rsassa_pss_with_parameters_verify_schema.json": true,
	}

	customFormats = []jsonschema.Format{
		{
			Name: "Asn",
			// For ASN.1 data we can validate the format is valid hex, but to decode
			// further we need to know the expected structure (and encoding) of the data.
			Validate: validateHex,
		},
		{
			Name: "Der",
			// For DER-encoded data, we can validate the format is valid hex, but to decode
			// further we need to know the expected structure of the data.
			Validate: validateHex,
		},
		{
			Name:     "EcCurve",
			Validate: validateCurve,
		},
		{
			Name:     "HexBytes",
			Validate: validateHex,
		},
		{
			Name: "BigInt",
			// For big integers, we can validate the format is valid hex but not much else.
			Validate: validateHex,
		},
		{
			Name:     "Pem",
			Validate: validatePem,
		},
	}
)

func validateHex(value any) error {
	strVal, ok := value.(string)
	if !ok {
		return fmt.Errorf("invalid non-string HexBytes value: %v", value)
	}

	_, err := hex.DecodeString(strVal)
	if err != nil {
		return fmt.Errorf("invalid HexBytes value: %v: %w", value, err)
	}

	return nil
}

func validatePem(value any) error {
	strVal, ok := value.(string)
	if !ok {
		return fmt.Errorf("invalid non-string Pem value: %v", value)
	}

	_, rest := pem.Decode([]byte(strVal))
	if len(rest) != 0 {
		return fmt.Errorf("invalid Pem value: unexpected trailing bytes %x", rest)
	}

	return nil
}

// TODO(XXX): standardize on curve name representation, use a schema enum instead of a type.
var curveNames = map[string]bool{
	"edwards25519":    true,
	"curve25519":      true,
	"edwards448":      true,
	"curve448":        true,
	"secp224r1":       true,
	"secp224k1":       true,
	"secp256r1":       true,
	"secp256k1":       true,
	"sect283k1":       true,
	"sect283r1":       true,
	"secp384r1":       true,
	"sect409k1":       true,
	"sect409r1":       true,
	"secp521r1":       true,
	"sect571k1":       true,
	"sect571r1":       true,
	"P-256K":          true,
	"P-256":           true,
	"P-384":           true,
	"P-521":           true,
	"FRP256v1":        true,
	"brainpoolP224r1": true,
	"brainpoolP224t1": true,
	"brainpoolP256r1": true,
	"brainpoolP256t1": true,
	"brainpoolP320r1": true,
	"brainpoolP320t1": true,
	"brainpoolP384r1": true,
	"brainpoolP384t1": true,
	"brainpoolP512r1": true,
	"brainpoolP512t1": true,
}

func validateCurve(value any) error {
	strVal, ok := value.(string)
	if !ok {
		return fmt.Errorf("invalid non-string EcCurve value: %v", value)
	}

	if _, ok := curveNames[strVal]; !ok {
		return fmt.Errorf("invalid EcCurve: unknown curve name: %q", strVal)
	}

	return nil
}

func lintVectorDir(schemaCompiler *jsonschema.Compiler, results *schemaLintResults, vectorDir string) error {
	err := filepath.WalkDir(vectorDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		if vectorRegex != nil && !vectorRegex.MatchString(d.Name()) {
			return nil
		}

		results.total++

		vectorData, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		if err := lintVectorTestGroups(vectorData, path); err != nil {
			log.Printf("❌ %q: %s\n", path, err)
			results.invalid++
			return nil
		}

		if err := lintVectorToSchema(schemaCompiler, vectorData, path, results); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	return nil
}

func lintVectorTestGroups(vectorData []byte, path string) error {
	var vector struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			Tests []struct {
				TcId int `json:"tcId"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(vectorData, &vector); err != nil {
		return fmt.Errorf("error decoding vector JSON data for test groups: %w", err)
	}

	// Within a vector file, test case IDs must be unique.
	testCaseIds := make(map[int]struct{})
	for _, tg := range vector.TestGroups {
		for _, test := range tg.Tests {
			if _, ok := testCaseIds[test.TcId]; ok {
				return fmt.Errorf("vector %q has duplicate tcId %d", path, test.TcId)
			}
			testCaseIds[test.TcId] = struct{}{}
		}
	}

	if testCount := len(testCaseIds); testCount != vector.NumberOfTests {
		return fmt.Errorf("vector %q declared %d tests in group, had %d", path, vector.NumberOfTests, testCount)
	}

	return nil
}

func lintVectorToSchema(schemaCompiler *jsonschema.Compiler, vectorData []byte, path string, results *schemaLintResults) error {
	var vector struct {
		Schema string `json:"schema"`
	}

	if err := json.Unmarshal(vectorData, &vector); err != nil {
		log.Printf("❌ %q: invalid vector JSON data: %s\n", path, err)
		results.invalid++
		return nil
	}

	if vector.Schema == "" {
		log.Printf("❌ %q: no schema specified\n", path)
		results.noSchema++
		return nil
	}

	if missingSchemas[vector.Schema] {
		log.Printf("⚠️ %q: ignoring missing schema %q\n", path, vector.Schema)
		results.ignored++
		return nil
	}

	schemaPath := filepath.Join(*schemaDirectory, vector.Schema)
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		log.Printf("❌ %q: referenced schema %q not found\n", path, vector.Schema)
		results.invalid++
		return nil
	}

	schema, err := schemaCompiler.Compile(schemaPath)
	if err != nil {
		log.Printf("❌ %q: invalid schema %q: %s\n", path, vector.Schema, err)
		results.invalid++
		return nil
	}

	var instance any
	if err := json.Unmarshal(vectorData, &instance); err != nil {
		log.Printf("❌ %q: invalid vector JSON data: %s\n", path, err)
		results.invalid++
		return nil
	}

	if err := schema.Validate(instance); err != nil {
		log.Printf("❌ %q: vector doesn't validate with schema: %s\n", path, err)
		results.invalid++
		return nil
	}

	log.Printf("✅ %q: validates with %q\n", path, vector.Schema)
	results.valid++
	return nil
}

type schemaLintResults struct {
	total, valid, invalid, noSchema, ignored int
}
