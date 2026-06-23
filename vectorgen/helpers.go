package vectorgen

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
)

// Options configures vectorgen mutating operations.
type Options struct {
	// SchemasFS is the filesystem containing schema files, used for both
	// schema-required field ordering on newly created files and for
	// post-merge validation. If nil, the embedded wycheproof.Schemas is used.
	SchemasFS fs.FS
}

// SourceFilter selects test groups by source.name and, optionally,
// source.version. An empty Version matches any version. Used by Add (for
// --into-group), Update (for the patch source), and Replace.
type SourceFilter struct {
	Name    string
	Version string
}

// ParseSourceFilter parses "name" or "name@version".
func ParseSourceFilter(s string) SourceFilter {
	if name, version, ok := strings.Cut(s, "@"); ok {
		return SourceFilter{Name: name, Version: version}
	}
	return SourceFilter{Name: s}
}

// String formats the filter as "name" or "name@version".
func (f SourceFilter) String() string {
	if f.Version == "" {
		return f.Name
	}
	return f.Name + "@" + f.Version
}

// Matches reports whether group's source field matches f.
func (f SourceFilter) Matches(group RawObject) (bool, error) {
	rawSrc, ok := group.Get("source")
	if !ok {
		return false, nil
	}
	src, err := parseObject(rawSrc)
	if err != nil {
		return false, fmt.Errorf("parsing source: %w", err)
	}

	nameVal, ok := src.Get("name")
	if !ok {
		return false, nil
	}
	var name string
	if err := json.Unmarshal(nameVal, &name); err != nil {
		return false, fmt.Errorf("decoding source.name: %w", err)
	}
	if name != f.Name {
		return false, nil
	}
	if f.Version == "" {
		return true, nil
	}

	verVal, ok := src.Get("version")
	if !ok {
		return false, nil
	}
	var version string
	if err := json.Unmarshal(verVal, &version); err != nil {
		return false, fmt.Errorf("decoding source.version: %w", err)
	}
	return version == f.Version, nil
}

// findSingleMatchingGroup returns the index of the one group whose source
// matches filter. Errors with a descriptive message if zero or more than one
// groups match. The displayLabel is used in error messages (e.g. "--into-group"
// vs. "source"); leave empty for a generic label.
func findSingleMatchingGroup(groups []jsontext.Value, filter SourceFilter, displayLabel string) (int, error) {
	if displayLabel == "" {
		displayLabel = "source"
	}
	var matches []int
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return 0, fmt.Errorf("group %d: %w", i, err)
		}
		match, err := filter.Matches(group)
		if err != nil {
			return 0, fmt.Errorf("group %d: %w", i, err)
		}
		if match {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("%s %q matched no group", displayLabel, filter.String())
	case 1:
		return matches[0], nil
	default:
		return 0, fmt.Errorf("%s %q matched %d groups; disambiguate with name@version", displayLabel, filter.String(), len(matches))
	}
}

// getTestGroups extracts the testGroups array as a slice of raw JSON values
// (one per group), leaving each group's bytes intact.
func getTestGroups(root RawObject) ([]jsontext.Value, error) {
	raw, ok := root.Get("testGroups")
	if !ok {
		return nil, errors.New("vector has no testGroups field")
	}
	var groups []jsontext.Value
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, fmt.Errorf("decoding testGroups: %w", err)
	}

	return groups, nil
}

// getTestsArray extracts the tests array of a group as a slice of raw JSON
// values, one per test.
func getTestsArray(group RawObject) ([]jsontext.Value, error) {
	raw, ok := group.Get("tests")
	if !ok {
		return nil, nil
	}
	var tests []jsontext.Value
	if err := json.Unmarshal(raw, &tests); err != nil {
		return nil, fmt.Errorf("decoding tests: %w", err)
	}

	return tests, nil
}

// eachTest invokes fn for every test in every group, in file order. Halts
// on the first error fn returns.
func eachTest(root RawObject, fn func(test jsontext.Value) error) error {
	groups, err := getTestGroups(root)
	if err != nil {
		return err
	}
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return fmt.Errorf("group %d: %w", i, err)
		}
		tests, err := getTestsArray(group)
		if err != nil {
			return fmt.Errorf("group %d: %w", i, err)
		}
		for _, t := range tests {
			if err := fn(t); err != nil {
				return err
			}
		}
	}
	return nil
}

// readTcId extracts the tcId integer from a test value.
func readTcId(test jsontext.Value) (int, error) {
	obj, err := parseObject(test)
	if err != nil {
		return 0, err
	}
	raw, ok := obj.Get("tcId")
	if !ok {
		return 0, errors.New("test has no tcId")
	}

	var id int
	if err := json.Unmarshal(raw, &id); err != nil {
		return 0, fmt.Errorf("decoding tcId: %w", err)
	}

	return id, nil
}

// jsonEqual reports whether two JSON values are semantically equal by
// canonicalizing both sides.
func jsonEqual(a, b jsontext.Value) bool {
	ac, bc := jsontext.Value(bytes.Clone(a)), jsontext.Value(bytes.Clone(b))
	if err := ac.Canonicalize(); err != nil {
		return false
	}
	if err := bc.Canonicalize(); err != nil {
		return false
	}
	return bytes.Equal(ac, bc)
}

// mustMarshal panics if v cannot be marshaled. Used for values we control.
func mustMarshal(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("vectorgen: mustMarshal: %v", err))
	}
	return b
}

// mustMarshalArray encodes a slice of raw JSON values as a JSON array,
// preserving each element's exact bytes.
func mustMarshalArray(vals []jsontext.Value) jsontext.Value {
	if len(vals) == 0 {
		return jsontext.Value("[]")
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, v := range vals {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(v)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// emptyObject returns a JSON empty object value.
func emptyObject() jsontext.Value { return jsontext.Value("{}") }

// assembleTopLevel builds the root object in schema-properties order.
//
// Keys present in values are inserted in the order listed in order. Any value
// keys not in order are appended at the end (alphabetically for determinism).
func assembleTopLevel(values map[string]jsontext.Value, order []string) RawObject {
	var root RawObject
	used := map[string]bool{}
	for _, name := range order {
		v, ok := values[name]
		if !ok {
			continue
		}
		root = append(root, ObjectMember[jsontext.Value]{Name: name, Value: v})
		used[name] = true
	}

	extras := slices.Sorted(maps.Keys(values))
	for _, name := range extras {
		if used[name] {
			continue
		}
		root = append(root, ObjectMember[jsontext.Value]{Name: name, Value: values[name]})
	}

	return root
}
