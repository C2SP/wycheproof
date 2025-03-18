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

func main() {
	schemaDirectory := flag.String("schemas-dir", "schemas", "directory containing schema files")
	vectorsDirectories := flag.String("vectors-dir", "testvectors_v1,testvectors", "comma separated directories containing vector files")
	vectorFilter := flag.String("vector-filter", "", "only validate vector files matching the provided pattern")

	flag.Parse()

	vectorDirectoryParts := strings.Split(*vectorsDirectories, ",")

	log.Printf("reading schemas from %q\n", *schemaDirectory)
	log.Printf("reading vectors from %q\n", vectorDirectoryParts)

	var vectorRegex *regexp.Regexp
	if *vectorFilter != "" {
		vectorRegex = regexp.MustCompile(*vectorFilter)
		log.Printf("filtering vectors with %q\n", *vectorFilter)
	}

	schemaCompiler := jsonschema.NewCompiler()

	for _, f := range customFormats {
		schemaCompiler.RegisterFormat(&f)
	}
	schemaCompiler.AssertFormat() // Opt in to format validation.

	var total, valid, invalid, noSchema, ignored int
	for _, vectorDir := range vectorDirectoryParts {
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

			vectorData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}

			total++

			var vector struct {
				Schema string `json:"schema"`
			}

			if err := json.Unmarshal(vectorData, &vector); err != nil {
				log.Printf("❌ %q: invalid vector JSON data: %s\n", path, err)
				invalid++
				return nil
			}

			if vector.Schema == "" {
				log.Printf("❌ %q: no schema specified\n", path)
				noSchema++
				return nil
			}

			if missingSchemas[vector.Schema] {
				log.Printf("⚠️ %q: ignoring missing schema %q\n", path, vector.Schema)
				ignored++
				return nil
			}

			schemaPath := filepath.Join(*schemaDirectory, vector.Schema)
			if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
				log.Printf("❌ %q: referenced schema %q not found\n", path, vector.Schema)
				invalid++
				return nil
			}

			schema, err := schemaCompiler.Compile(schemaPath)
			if err != nil {
				log.Printf("❌ %q: invalid schema %q: %s\n", path, vector.Schema, err)
				invalid++
				return nil
			}

			var instance any
			if err := json.Unmarshal(vectorData, &instance); err != nil {
				log.Printf("❌ %q: invalid vector JSON data: %s\n", path, err)
				invalid++
				return nil
			}

			if err := schema.Validate(instance); err != nil {
				log.Printf("❌ %q: vector doesn't validate with schema: %s\n", path, err)
				invalid++
				return nil
			}

			log.Printf("✅ %q: validates with %q\n", path, vector.Schema)
			valid++
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking directory: %v\n", err)
			os.Exit(1)
		}
	}

	log.Printf("linted %d vector files\n", total)
	log.Printf("valid: %d\n", valid)
	log.Printf("invalid: %d\n", invalid)
	log.Printf("no schema: %d\n", noSchema)
	log.Printf("ignored: %d\n", ignored)

	os.Exit(invalid)
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
			// TODO(XXX): validate "Asn" format.
			Validate: noValidateFormat,
		},
		{
			Name: "Der",
			// For DER-encoded data, we can validate the format is valid hex, but to decode
			// further we need to know the expected structure of the data.
			Validate: validateHex,
		},
		{
			Name: "EcCurve",
			// TODO(XXX): validate "EcCurve" format.
			Validate: noValidateFormat,
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

// noValidateFormat is a placeholder Format.Validate callback that performs no validation of the input.
func noValidateFormat(_ any) error {
	return nil
}

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
