package vectorgen

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/c2sp/wycheproof"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// LintOptions configures Lint.
type LintOptions struct {
	// SchemasFS is the filesystem containing schema files. If nil, the
	// embedded wycheproof.Schemas is used.
	SchemasFS fs.FS

	// VectorDirs lists directories to scan for vector files. If empty, scans
	// "testvectors_v1" on disk.
	VectorDirs []string

	// Filter, if non-nil, restricts linting to vector filenames matching the
	// regexp.
	Filter *regexp.Regexp

	// Log, if non-nil, receives a one-line message per vector processed.
	Log func(format string, args ...any)
}

// LintResults summarizes a Lint run.
type LintResults struct {
	Total    int
	Valid    int
	Invalid  int
	NoSchema int
}

// ErrNoSchema is returned by LintBytes when a vector is structurally valid
// but does not declare a schema. Callers that categorize results (e.g.
// vectorgen lint) use errors.Is to distinguish it from real validation
// failures.
var ErrNoSchema = errors.New("no schema specified")

// Lint walks the configured vector directories and validates every *.json
// vector against its declared schema and against structural invariants
// (single test-group type per file, unique tcIds, accurate numberOfTests).
//
// Returns the per-category counts. Lint itself only returns an error for
// unrecoverable I/O problems; per-vector validation failures are recorded in
// the results.
func Lint(opts LintOptions) (LintResults, error) {
	if opts.Log == nil {
		opts.Log = func(string, ...any) {}
	}
	if len(opts.VectorDirs) == 0 {
		opts.VectorDirs = []string{"testvectors_v1"}
	}

	compiler, err := newSchemaCompiler(opts.SchemasFS)
	if err != nil {
		return LintResults{}, fmt.Errorf("building schema compiler: %w", err)
	}

	var results LintResults
	for _, dir := range opts.VectorDirs {
		if err := lintDir(compiler, dir, opts.Filter, opts.Log, &results); err != nil {
			return results, err
		}
	}
	return results, nil
}

// LintBytes validates a single vector file's bytes against its declared
// schema and against structural invariants. Returns nil if the vector is
// fully valid, ErrNoSchema if it declares no schema, or a wrapped error
// describing the validation failure.
//
// For bulk validation, Lint reuses a single compiled schema set; prefer it
// over many LintBytes calls.
func LintBytes(data []byte, schemasFS fs.FS) error {
	compiler, err := newSchemaCompiler(schemasFS)
	if err != nil {
		return fmt.Errorf("building schema compiler: %w", err)
	}
	return lintBytesWith(compiler, data)
}

// lintBytesWith does the structural and schema validation work, reusing a
// pre-built compiler. The split lets Lint amortize compiler construction
// across many files; LintBytes is a one-shot wrapper.
func lintBytesWith(compiler *jsonschema.Compiler, data []byte) error {
	if err := lintTestGroups(data); err != nil {
		return err
	}

	var ref struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		return fmt.Errorf("invalid vector JSON: %w", err)
	}
	if ref.Schema == "" {
		return ErrNoSchema
	}

	schema, err := compiler.Compile(ref.Schema)
	if err != nil {
		return fmt.Errorf("invalid schema %q: %w", ref.Schema, err)
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return fmt.Errorf("invalid vector JSON: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("doesn't validate with schema: %w", err)
	}
	return nil
}

func lintDir(compiler *jsonschema.Compiler, dir string, filter *regexp.Regexp, logf func(string, ...any), results *LintResults) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if filter != nil && !filter.MatchString(d.Name()) {
			return nil
		}

		results.Total++

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		switch err := lintBytesWith(compiler, data); {
		case err == nil:
			logf("✅ %q: valid", path)
			results.Valid++
		case errors.Is(err, ErrNoSchema):
			logf("❌ %q: %s", path, err)
			results.NoSchema++
		default:
			logf("❌ %q: %s", path, err)
			results.Invalid++
		}
		return nil
	})
}

func lintTestGroups(data []byte) error {
	var v struct {
		NumberOfTests int `json:"numberOfTests"`
		TestGroups    []struct {
			Type  string `json:"type"`
			Tests []struct {
				TcId int `json:"tcId"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("decoding test groups: %w", err)
	}

	types := make(map[string]bool)
	for _, tg := range v.TestGroups {
		if tg.Type != "" {
			types[tg.Type] = true
		}
	}
	if len(types) > 1 {
		var names []string
		for t := range types {
			names = append(names, t)
		}
		return fmt.Errorf("multiple test group types: %v (expected only one per file)", names)
	}

	ids := make(map[int]struct{})
	for _, tg := range v.TestGroups {
		for _, t := range tg.Tests {
			if _, ok := ids[t.TcId]; ok {
				return fmt.Errorf("duplicate tcId %d", t.TcId)
			}
			ids[t.TcId] = struct{}{}
		}
	}
	if len(ids) != v.NumberOfTests {
		return fmt.Errorf("declared %d tests, found %d", v.NumberOfTests, len(ids))
	}
	return nil
}

func newSchemaCompiler(schemasFS fs.FS) (*jsonschema.Compiler, error) {
	if schemasFS == nil {
		schemasFS = wycheproof.Schemas
	}
	compiler := jsonschema.NewCompiler()
	for _, f := range customFormats {
		compiler.RegisterFormat(&f)
	}
	compiler.AssertFormat()

	if err := fs.WalkDir(schemasFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := fs.ReadFile(schemasFS, path)
		if err != nil {
			return fmt.Errorf("read schema %s: %w", path, err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse schema %s: %w", path, err)
		}
		return compiler.AddResource(path, doc)
	}); err != nil {
		return nil, err
	}
	return compiler, nil
}

var customFormats = []jsonschema.Format{
	{Name: "Asn", Validate: validateHex},
	{Name: "Der", Validate: validateHex},
	{Name: "EcCurve", Validate: validateCurve},
	{Name: "HexBytes", Validate: validateHex},
	{Name: "CompressedHexBytes", Validate: validateCompressedHex},
	{Name: "BigInt", Validate: validateHex},
	{Name: "Pem", Validate: validatePem},
}

func validateHex(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string HexBytes value")
	}
	if s != strings.ToLower(s) {
		return errors.New("non-lowercase HexBytes value")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("invalid HexBytes value: %w", err)
	}
	return nil
}

func validateCompressedHex(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string CompressedHexBytes value")
	}
	if s != strings.ToLower(s) {
		return errors.New("non-lowercase CompressedHexBytes value")
	}
	compressed, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid CompressedHexBytes value: %w", err)
	}
	br := bytes.NewReader(compressed)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return fmt.Errorf("invalid CompressedHexBytes value: %w", err)
	}
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return fmt.Errorf("invalid CompressedHexBytes value: %w", err)
	}
	if err := zr.Close(); err != nil {
		return fmt.Errorf("invalid CompressedHexBytes value: %w", err)
	}
	if br.Len() != 0 {
		return fmt.Errorf("invalid CompressedHexBytes value: %d trailing bytes after zlib stream", br.Len())
	}
	return nil
}

func validatePem(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string Pem value")
	}
	if _, rest := pem.Decode([]byte(s)); len(rest) != 0 {
		return fmt.Errorf("invalid Pem value: trailing bytes %x", rest)
	}
	return nil
}

func validateCurve(value any) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("non-string EcCurve value")
	}
	if !curveNames[s] {
		return fmt.Errorf("unknown EcCurve name: %q", s)
	}
	return nil
}

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
