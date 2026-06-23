package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
)

// Replace swaps the single group matching filter in the vector file at
// vectorPath with a fresh group built from env's GroupTemplate and Tests.
// The new group is inserted at the original group's position. Every test in
// the file is renumbered sequentially from 1 in file order; numberOfTests is
// recomputed.
//
// Errors:
//   - The filter matches zero or more than one group.
//   - The envelope has top-level metadata fields set (Algorithm, Schema,
//     Header) — those are only meaningful when creating a new file.
//   - The envelope has IntoGroup set — that's an Add-only mode.
//
// On schema-validation failure the candidate output is written to
// vectorPath+".rej" and the original is left untouched.
func Replace(vectorPath string, env AddEnvelope, filter SourceFilter, opts Options) error {
	if filter.Name == "" {
		return errors.New("filter.Name is required")
	}
	if len(env.Tests) == 0 {
		return errors.New("envelope.tests is empty")
	}
	if err := rejectSuppliedTcIds(env.Tests); err != nil {
		return err
	}
	if len(env.GroupTemplate) == 0 {
		return errors.New("envelope.groupTemplate is required")
	}
	if env.Algorithm != "" || env.Schema != "" || len(env.Header) > 0 {
		return errors.New("envelope must not set algorithm/schema/header for replace (those are for new files)")
	}
	if env.IntoGroup != "" {
		return errors.New("envelope.intoGroup is for add, not replace")
	}

	existing, err := os.ReadFile(vectorPath)
	if err != nil {
		return err
	}
	root, err := parseObject(existing)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", vectorPath, err)
	}

	root, err = replaceGroup(root, filter, env.GroupTemplate, env.Tests)
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = renumberAllTests(root)
	if err != nil {
		return err
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// replaceGroup finds the single group matching filter and swaps it for a
// freshly built group (template + tests) at the same position.
func replaceGroup(root RawObject, filter SourceFilter, groupTemplate jsontext.Value, tests []jsontext.Value) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	idx, err := findSingleMatchingGroup(groups, filter, "source")
	if err != nil {
		return nil, err
	}

	newGroup, err := parseObject(groupTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing groupTemplate: %w", err)
	}
	if _, exists := newGroup.Get("tests"); exists {
		return nil, errors.New("groupTemplate must not contain a tests field; pass tests separately")
	}
	// Insert tests with placeholder numbering; renumberAllTests will rewrite
	// them in their final positions based on file order.
	numbered, err := renumberTests(tests, 1)
	if err != nil {
		return nil, err
	}
	newGroup = newGroup.Set("tests", mustMarshalArray(numbered))
	encoded, err := json.Marshal(&newGroup)
	if err != nil {
		return nil, err
	}
	groups[idx] = encoded
	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// renumberAllTests rewrites every test's tcId across every group, starting
// from 1 and incrementing in file order. Used by Replace because a swapped
// group may differ in size from the one it replaced.
func renumberAllTests(root RawObject) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	id := 1
	for gi, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		tests, err := getTestsArray(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}
		if len(tests) == 0 {
			continue
		}

		renumbered, err := renumberTests(tests, id)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		id += len(tests)
		group = group.Set("tests", mustMarshalArray(renumbered))

		encoded, err := json.Marshal(&group)
		if err != nil {
			return nil, err
		}
		groups[gi] = encoded
	}

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}
