package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"slices"
)

// Update applies env to the vector file at vectorPath, modifying matched
// test objects in place.
//
// The result is validated before writing. On failure the candidate is written
// to vectorPath+".rej" and the original is untouched.
func Update(vectorPath string, env UpdateEnvelope, opts Options) error {
	if env.Source == "" {
		return errors.New("envelope.source is required")
	}
	if len(env.Patches) == 0 {
		return errors.New("envelope.patches is empty")
	}

	data, err := os.ReadFile(vectorPath)
	if err != nil {
		return err
	}

	root, err := parseObject(data)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", vectorPath, err)
	}

	var ref struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		return fmt.Errorf("decoding schema reference: %w", err)
	}
	if ref.Schema == "" {
		return errors.New("vector has no schema field")
	}

	propOrder, err := testVectorProperties(opts.SchemasFS, ref.Schema)
	if err != nil {
		return fmt.Errorf("resolving schema property order: %w", err)
	}

	root, err = applyPatches(root, env, propOrder)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// UpdateEnvelope describes a vectorgen update operation's input.
type UpdateEnvelope struct {
	// Source identifies which groups to update (matched against
	// group.source.name, optionally "name@version").
	Source string `json:"source"`

	// Patches lists per-test overrides. Each patch must contain a tcId.
	Patches []jsontext.Value `json:"patches"`

	// Overwrite permits patches to replace existing field values. Without it,
	// a patch that names an already-present field with a byte-different value
	// is an error.
	Overwrite bool `json:"-"`

	// Partial permits patches to cover a strict subset of matching groups'
	// tests. Without it, every test in every matching group must appear in
	// patches.
	Partial bool `json:"-"`
}

// applyPatches walks root.testGroups, selects groups matching env.Source, and
// applies env.Patches to their tests.
//
// Per-test merge uses propOrder to position newly added keys.
func applyPatches(root RawObject, env UpdateEnvelope, propOrder []string) (RawObject, error) {
	filter := ParseSourceFilter(env.Source)

	patchByTcId, err := indexPatches(env.Patches)
	if err != nil {
		return nil, err
	}

	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}

	applied := map[int]bool{} // tcIds we actually patched
	matchedAny := false
	for gi, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		match, err := filter.Matches(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}
		if !match {
			continue
		}
		matchedAny = true

		tests, err := getTestsArray(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		for ti, t := range tests {
			tcId, err := readTcId(t)
			if err != nil {
				return nil, fmt.Errorf("group %d test %d: %w", gi, ti, err)
			}
			patch, ok := patchByTcId[tcId]
			if !ok {
				continue
			}

			updated, err := mergePatch(t, patch, propOrder, env.Overwrite)
			if err != nil {
				return nil, fmt.Errorf("group %d tcId %d: %w", gi, tcId, err)
			}

			tests[ti] = updated
			applied[tcId] = true
		}

		if !env.Partial {
			missing := []int{}
			for _, t := range tests {
				tcId, _ := readTcId(t)
				if _, ok := patchByTcId[tcId]; !ok {
					missing = append(missing, tcId)
				}
			}

			if len(missing) > 0 {
				return nil, fmt.Errorf("group %d (source %q) has %d unpatched tests (tcIds %v); pass --partial to allow partial updates",
					gi, env.Source, len(missing), missing)
			}
		}

		group = group.Set("tests", mustMarshalArray(tests))
		encoded, err := json.Marshal(&group)
		if err != nil {
			return nil, err
		}

		groups[gi] = encoded
	}

	if !matchedAny {
		return nil, fmt.Errorf("source %q matched no group", env.Source)
	}

	// Verify every patch tcId was used.
	var unused []int
	for tcId := range patchByTcId {
		if !applied[tcId] {
			unused = append(unused, tcId)
		}
	}
	if len(unused) > 0 {
		slices.Sort(unused)
		return nil, fmt.Errorf("patches reference tcIds not present in any matching group: %v", unused)
	}

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// indexPatches converts the patches array into a tcId-keyed map. Errors on
// duplicate or missing tcId.
func indexPatches(patches []jsontext.Value) (map[int]RawObject, error) {
	out := make(map[int]RawObject, len(patches))
	for i, p := range patches {
		obj, err := parseObject(p)
		if err != nil {
			return nil, fmt.Errorf("patch %d: %w", i, err)
		}
		raw, ok := obj.Get("tcId")
		if !ok {
			return nil, fmt.Errorf("patch %d: missing tcId", i)
		}
		var tcId int
		if err := json.Unmarshal(raw, &tcId); err != nil {
			return nil, fmt.Errorf("patch %d: decoding tcId: %w", i, err)
		}
		if _, dup := out[tcId]; dup {
			return nil, fmt.Errorf("patch %d: duplicate tcId %d", i, tcId)
		}
		out[tcId] = obj
	}
	return out, nil
}

// mergePatch applies patch to test.
//
// Existing keys are replaced only when overwrite is true, otherwise a
// byte-different replacement is an error. New keys are inserted at the position
// implied by propOrder.
func mergePatch(test jsontext.Value, patch RawObject, propOrder []string, overwrite bool) (jsontext.Value, error) {
	obj, err := parseObject(test)
	if err != nil {
		return nil, err
	}

	for _, m := range patch {
		if m.Name == "tcId" {
			continue // tcId is the join key, not data to merge
		}

		if idx := obj.IndexOf(m.Name); idx >= 0 {
			if jsonEqual(obj[idx].Value, m.Value) {
				continue
			}

			if !overwrite {
				return nil, fmt.Errorf("field %q already exists with different value; pass --overwrite to replace", m.Name)
			}

			obj[idx].Value = m.Value
			continue
		}

		// Insert new key at the position implied by the schema's property order.
		obj = insertByPropertyOrder(obj, propOrder, m.Name, m.Value)
	}

	encoded, err := json.Marshal(&obj)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

// insertByPropertyOrder inserts name=value at the position implied by order:
// just before the leftmost existing member whose name comes at or after name
// in order. If no such member exists (or name is not in order), appends at
// the end.
func insertByPropertyOrder(obj RawObject, order []string, name string, value jsontext.Value) RawObject {
	pos := slices.Index(order, name)
	if pos < 0 {
		return append(obj, ObjectMember[jsontext.Value]{Name: name, Value: value})
	}
	insertAt := len(obj)
	for i := range obj {
		objPos := slices.Index(order, obj[i].Name)
		if objPos < 0 {
			continue
		}
		if objPos >= pos {
			insertAt = i
			break
		}
	}
	return obj.InsertAt(insertAt, name, value)
}
