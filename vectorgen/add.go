package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
)

// Add applies env to the vector file at vectorPath. If the file does not
// exist, it is created from env's top-level fields. If it exists, the
// behavior depends on env.IntoGroup: when set, tests are appended into the
// matching existing group; otherwise a new group is appended.
//
// Appending a group whose fields and tests are identical (ignoring tcIds) to
// an existing group is an error — that's the signature of a generator re-run.
// Use IntoGroup to extend the existing group or Replace to regenerate it.
//
// The result is schema-validated before writing. On validation failure the
// merged content is written to vectorPath+".rej" and the original is left
// untouched.
func Add(vectorPath string, env AddEnvelope, opts Options) error {
	if len(env.Tests) == 0 {
		return errors.New("envelope tests are empty")
	}
	if err := rejectSuppliedTcIds(env.Tests); err != nil {
		return err
	}

	existing, err := os.ReadFile(vectorPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return addNewFile(vectorPath, env, opts)
	case err != nil:
		return err
	}

	root, err := parseObject(existing)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", vectorPath, err)
	}

	if env.IntoGroup != "" {
		root, err = appendIntoGroup(root, env.IntoGroup, env.Tests)
	} else {
		if len(env.GroupTemplate) == 0 {
			return errors.New("envelope is missing groupTemplate (and intoGroup is not set)")
		}
		root, err = appendNewGroup(root, env.GroupTemplate, env.Tests)
	}
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// AddEnvelope describes a single vectorgen add operation's input.
type AddEnvelope struct {
	// File-level fields used only when creating a new vector file. Ignored
	// when appending to an existing file.
	Algorithm string   `json:"algorithm,omitempty"`
	Schema    string   `json:"schema,omitempty"`
	Header    []string `json:"header,omitempty"`

	// GroupTemplate is the new test group's object minus its tests array.
	// Required for append-group mode. Ignored when IntoGroup is set.
	GroupTemplate jsontext.Value `json:"groupTemplate,omitempty"`

	// Tests are the new test objects to add. They must not include a tcId
	// field; the tool assigns them.
	Tests []jsontext.Value `json:"tests"`

	// Notes to merge into the file's top-level notes. Conflicting entries
	// (same key, different content) are rejected.
	Notes RawObject `json:"notes,omitempty"`

	// IntoGroup, if non-empty, appends Tests into an existing group with the
	// given source name (and optional version, separated by "@"). When set,
	// GroupTemplate is ignored.
	//
	// This field is not deserialized from the envelope; it is set by callers
	// (typically the CLI's --into-group flag).
	IntoGroup string `json:"-"`
}

// addNewFile is Add's helper for initializing a brand-new file. The target
// does not exist; we synthesize a new file from env using schema-properties
// field ordering at the top level.
func addNewFile(vectorPath string, env AddEnvelope, opts Options) error {
	if env.Algorithm == "" {
		return errors.New("creating a new file requires envelope.algorithm")
	}
	if env.Schema == "" {
		return errors.New("creating a new file requires envelope.schema")
	}
	if len(env.GroupTemplate) == 0 {
		return errors.New("creating a new file requires envelope.groupTemplate")
	}

	schemaOrder, err := topLevelProperties(opts.SchemasFS, env.Schema)
	if err != nil {
		return fmt.Errorf("reading schema %s: %w", env.Schema, err)
	}

	values := map[string]jsontext.Value{
		"algorithm":     mustMarshal(env.Algorithm),
		"schema":        mustMarshal(env.Schema),
		"numberOfTests": jsontext.Value("0"),
		"notes":         emptyObject(),
		"testGroups":    jsontext.Value("[]"),
	}
	if len(env.Header) > 0 {
		values["header"] = mustMarshal(env.Header)
	}

	root := assembleTopLevel(values, schemaOrder)

	root, err = appendNewGroup(root, env.GroupTemplate, env.Tests)
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// appendNewGroup appends a fresh group to root.testGroups.
//
// The group is built from groupTemplate (a JSON object value) plus a freshly
// assigned tests array.
func appendNewGroup(root RawObject, groupTemplate jsontext.Value, tests []jsontext.Value) (RawObject, error) {
	group, err := parseObject(groupTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing groupTemplate: %w", err)
	}
	if _, exists := group.Get("tests"); exists {
		return nil, errors.New("groupTemplate must not contain a tests field; pass tests separately")
	}

	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	for i, g := range groups {
		existing, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		same, err := sameGroupIgnoringTcIds(existing, group, tests)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		if same {
			return nil, fmt.Errorf("new group is identical to existing group %d (same fields and tests; likely a generator re-run); use IntoGroup to append tests or Replace to regenerate the group", i)
		}
	}

	startID, err := nextTcId(root)
	if err != nil {
		return nil, err
	}

	numbered, err := renumberTests(tests, startID)
	if err != nil {
		return nil, err
	}
	group = group.Set("tests", mustMarshalArray(numbered))

	groupVal, err := json.Marshal(&group)
	if err != nil {
		return nil, fmt.Errorf("encoding group: %w", err)
	}
	groups = append(groups, jsontext.Value(groupVal))

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// appendIntoGroup appends tests to an existing group identified by source.
// source may be "name" or "name@version".
func appendIntoGroup(root RawObject, source string, tests []jsontext.Value) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	idx, err := findSingleMatchingGroup(groups, ParseSourceFilter(source), "--into-group")
	if err != nil {
		return nil, err
	}

	startID, err := nextTcId(root)
	if err != nil {
		return nil, err
	}
	numbered, err := renumberTests(tests, startID)
	if err != nil {
		return nil, err
	}

	group, err := parseObject(groups[idx])
	if err != nil {
		return nil, err
	}
	existingTests, err := getTestsArray(group)
	if err != nil {
		return nil, err
	}
	existingTests = append(existingTests, numbered...)
	group = group.Set("tests", mustMarshalArray(existingTests))

	updated, err := json.Marshal(&group)
	if err != nil {
		return nil, err
	}
	groups[idx] = updated
	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// sameGroupIgnoringTcIds reports whether existing has the same fields as
// template and the same tests (ignoring tcId) as tests. A match means Add is
// about to append an exact duplicate of an existing group.
func sameGroupIgnoringTcIds(existing RawObject, template RawObject, tests []jsontext.Value) (bool, error) {
	existingTests, err := getTestsArray(existing)
	if err != nil {
		return false, err
	}
	if len(existingTests) != len(tests) {
		return false, nil
	}

	var meta RawObject
	for _, m := range existing {
		if m.Name != "tests" {
			meta = append(meta, m)
		}
	}
	metaVal, err := json.Marshal(&meta)
	if err != nil {
		return false, err
	}
	templateVal, err := json.Marshal(&template)
	if err != nil {
		return false, err
	}
	if !jsonEqual(metaVal, templateVal) {
		return false, nil
	}

	for i, et := range existingTests {
		obj, err := parseObject(et)
		if err != nil {
			return false, err
		}
		var stripped RawObject
		for _, m := range obj {
			if m.Name != "tcId" {
				stripped = append(stripped, m)
			}
		}
		strippedVal, err := json.Marshal(&stripped)
		if err != nil {
			return false, err
		}
		if !jsonEqual(strippedVal, tests[i]) {
			return false, nil
		}
	}
	return true, nil
}

// mergeNotes inserts each note from add into root.notes. Conflicting entries
// (same key, byte-different value) are rejected; insertion order matches the
// add envelope.
func mergeNotes(root RawObject, add RawObject) (RawObject, error) {
	var notes RawObject
	if raw, ok := root.Get("notes"); ok {
		var err error
		notes, err = parseObject(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing notes: %w", err)
		}
	}
	for _, m := range add {
		if existing, ok := notes.Get(m.Name); ok {
			if !jsonEqual(existing, m.Value) {
				return nil, fmt.Errorf("notes[%q] already exists with different content", m.Name)
			}
			continue
		}
		notes = append(notes, m)
	}
	encoded, err := json.Marshal(&notes)
	if err != nil {
		return nil, err
	}
	return root.Set("notes", encoded), nil
}

// recomputeNumberOfTests counts every test across every group and writes the
// total to root.numberOfTests, creating the field if absent.
func recomputeNumberOfTests(root RawObject) (RawObject, error) {
	total := 0
	if err := eachTest(root, func(jsontext.Value) error {
		total++
		return nil
	}); err != nil {
		return nil, err
	}
	return root.Set("numberOfTests", jsontext.Value(strconv.Itoa(total))), nil
}

// nextTcId returns max(tcId across all tests in all groups) + 1, or 1 if the
// file currently has no tests.
func nextTcId(root RawObject) (int, error) {
	maxID := 0
	err := eachTest(root, func(t jsontext.Value) error {
		id, err := readTcId(t)
		if err != nil {
			return err
		}
		if id > maxID {
			maxID = id
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return maxID + 1, nil
}

// rejectSuppliedTcIds errors if an envelope-supplied test carries a tcId.
// The tool is the sole authority on numbering; silently renumbering would
// hide drift between the operator's numbering and the file's.
func rejectSuppliedTcIds(tests []jsontext.Value) error {
	for i, t := range tests {
		obj, err := parseObject(t)
		if err != nil {
			return fmt.Errorf("test %d: %w", i, err)
		}
		if obj.IndexOf("tcId") >= 0 {
			return fmt.Errorf("test %d: tests must not include a tcId field (the tool assigns them)", i)
		}
	}
	return nil
}

// renumberTests returns a parallel slice with tcId set to startID, startID+1,
// ... Existing tcIds are rewritten (Replace renumbers whole files this way);
// envelope-supplied tests are checked by rejectSuppliedTcIds before reaching
// here. Newly-inserted tcIds appear as the first field, matching existing
// vectors.
func renumberTests(tests []jsontext.Value, startID int) ([]jsontext.Value, error) {
	out := make([]jsontext.Value, len(tests))
	for i, t := range tests {
		obj, err := parseObject(t)
		if err != nil {
			return nil, fmt.Errorf("test %d: %w", i, err)
		}
		tcId := jsontext.Value(strconv.Itoa(startID + i))
		if obj.IndexOf("tcId") < 0 {
			obj = obj.InsertAt(0, "tcId", tcId)
		} else {
			obj = obj.Set("tcId", tcId)
		}
		encoded, err := json.Marshal(&obj)
		if err != nil {
			return nil, fmt.Errorf("test %d: %w", i, err)
		}
		out[i] = encoded
	}
	return out, nil
}

// finalizeAndWrite formats root, validates it, and writes atomically.
//
// On validation failure the candidate output is written to vectorPath+".rej"
// and the original (if any) is left untouched.
func finalizeAndWrite(vectorPath string, root RawObject, opts Options) error {
	out, err := marshalObject(root)
	if err != nil {
		return fmt.Errorf("encoding result: %w", err)
	}

	err = LintBytes(out, opts.SchemasFS)
	if err == nil {
		return writeAtomic(vectorPath, out)
	}

	rej := vectorPath + ".rej"
	if writeErr := os.WriteFile(rej, out, 0o644); writeErr != nil {
		return fmt.Errorf("%w (and failed to write %s: %v)", err, rej, writeErr)
	}

	return fmt.Errorf("%w (candidate written to %s)", err, rej)
}
