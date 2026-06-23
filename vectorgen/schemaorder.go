package vectorgen

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/c2sp/wycheproof"
)

// topLevelProperties returns the top-level properties of schemaName in
// declaration order. Used to position fields when synthesizing a new vector
// file.
func topLevelProperties(schemasFS fs.FS, schemaName string) ([]string, error) {
	root, err := loadSchema(schemasFS, schemaName)
	if err != nil {
		return nil, err
	}
	return propertyNames(root)
}

// testVectorProperties returns the test-vector object's properties in
// declaration order, by walking the schema from the top-level down through
// testGroups.items -> tests.items, following both same-document and
// cross-document $refs.
//
// The returned slice is the canonical order vectorgen.Update uses to position
// newly added keys.
func testVectorProperties(schemasFS fs.FS, schemaName string) ([]string, error) {
	r := newSchemaResolver(schemasFS)
	root, err := r.load(schemaName)
	if err != nil {
		return nil, err
	}

	testGroupItems, err := r.navigate(schemaNode{obj: root, root: root}, "properties", "testGroups", "items")
	if err != nil {
		return nil, fmt.Errorf("locating testGroups.items: %w", err)
	}

	testItems, err := r.navigate(testGroupItems, "properties", "tests", "items")
	if err != nil {
		return nil, fmt.Errorf("locating tests.items: %w", err)
	}

	return propertyNames(testItems.obj)
}

// loadSchema reads and parses schemaName from schemasFS (or the embedded FS
// when schemasFS is nil), returning the schema's root object.
func loadSchema(schemasFS fs.FS, schemaName string) (RawObject, error) {
	if schemasFS == nil {
		schemasFS = wycheproof.Schemas
	}

	data, err := fs.ReadFile(schemasFS, schemaName)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}

	root, err := parseObject(data)
	if err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}

	return root, nil
}

// propertyNames returns the keys of obj's "properties" object in declaration
// order.
func propertyNames(obj RawObject) ([]string, error) {
	propsVal, ok := obj.Get("properties")
	if !ok {
		return nil, errors.New("schema object has no properties")
	}

	props, err := parseObject(propsVal)
	if err != nil {
		return nil, fmt.Errorf("parsing properties: %w", err)
	}

	names := make([]string, len(props))
	for i := range props {
		names[i] = props[i].Name
	}

	return names, nil
}

// schemaNode pairs a sub-object with the document it lives in. The document
// is what subsequent same-document "#/" $refs resolve against; carrying it
// alongside the object lets us follow cross-document refs without losing
// track of which document we're now reading from.
type schemaNode struct {
	obj  RawObject
	root RawObject
}

// schemaResolver loads and caches schema documents, following $refs (both
// "#/..." within the current document and "other.json#/..." across documents).
type schemaResolver struct {
	fs   fs.FS
	docs map[string]RawObject // parsed root by schema name
}

func newSchemaResolver(schemasFS fs.FS) *schemaResolver {
	if schemasFS == nil {
		schemasFS = wycheproof.Schemas
	}

	return &schemaResolver{fs: schemasFS, docs: map[string]RawObject{}}
}

// load reads schemaName, caching the parsed result.
func (r *schemaResolver) load(schemaName string) (RawObject, error) {
	if doc, ok := r.docs[schemaName]; ok {
		return doc, nil
	}

	data, err := fs.ReadFile(r.fs, schemaName)
	if err != nil {
		return nil, fmt.Errorf("read schema %q: %w", schemaName, err)
	}

	root, err := parseObject(data)
	if err != nil {
		return nil, fmt.Errorf("parse schema %q: %w", schemaName, err)
	}
	r.docs[schemaName] = root

	return root, nil
}

// navigate walks node.obj following path, dereferencing $refs as it goes.
// Returns the final resolved node (so callers reading further "#/" refs from
// the result use the correct document root).
func (r *schemaResolver) navigate(node schemaNode, path ...string) (schemaNode, error) {
	cur, err := r.resolve(node)
	if err != nil {
		return schemaNode{}, err
	}

	for _, step := range path {
		next, ok := cur.obj.Get(step)
		if !ok {
			return schemaNode{}, fmt.Errorf("path step %q not found", step)
		}

		nextObj, err := parseObject(next)
		if err != nil {
			return schemaNode{}, fmt.Errorf("step %q: %w", step, err)
		}

		cur, err = r.resolve(schemaNode{obj: nextObj, root: cur.root})
		if err != nil {
			return schemaNode{}, err
		}
	}

	return cur, nil
}

// resolve dereferences node.obj if it carries a $ref, following same-document
// and cross-document refs. Same-document refs preserve node.root; cross-doc
// refs switch to the referenced document's root. Returns node unchanged if no
// $ref is present.
func (r *schemaResolver) resolve(node schemaNode) (schemaNode, error) {
	refVal, ok := node.obj.Get("$ref")
	if !ok {
		return node, nil
	}

	var ref string
	if err := json.Unmarshal(refVal, &ref); err != nil {
		return schemaNode{}, fmt.Errorf("decoding $ref: %w", err)
	}

	docPart, fragment, _ := strings.Cut(ref, "#")
	root := node.root
	if docPart != "" {
		var err error
		root, err = r.load(docPart)
		if err != nil {
			return schemaNode{}, fmt.Errorf("$ref %q: %w", ref, err)
		}
	}

	if fragment == "" {
		// "other.json" with no fragment refers to the entire document.
		return schemaNode{obj: root, root: root}, nil
	}
	if !strings.HasPrefix(fragment, "/") {
		return schemaNode{}, fmt.Errorf("$ref %q: fragment must start with '/'", ref)
	}

	cur := root
	for _, step := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
		v, ok := cur.Get(step)
		if !ok {
			return schemaNode{}, fmt.Errorf("$ref %q: step %q not found", ref, step)
		}
		next, err := parseObject(v)
		if err != nil {
			return schemaNode{}, fmt.Errorf("$ref %q step %q: %w", ref, step, err)
		}
		cur = next
	}

	return schemaNode{obj: cur, root: root}, nil
}
