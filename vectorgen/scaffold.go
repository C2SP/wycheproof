package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

// ScaffoldAdd returns a placeholder AddEnvelope JSON suitable as a starting
// template for `vectorgen add --create`.
//
// The envelope is populated from the named schema: top-level fields, one
// placeholder group, one placeholder test.
//
// Constrained fields (enums, formats) get angle-bracket hint strings like
// "<one of: A, B>" or "<hex bytes>" so operators can see at a glance what
// each field expects.
//
// The returned bytes are formatted (multi-line, indented) and end in a
// trailing newline, ready to write to a file or pipe to `vectorgen add`.
func ScaffoldAdd(schemaName string, opts Options) ([]byte, error) {
	r := newSchemaResolver(opts.SchemasFS)
	root, err := r.load(schemaName)
	if err != nil {
		return nil, err
	}
	rootNode := schemaNode{obj: root, root: root}

	algorithm, err := r.scalarPlaceholder(rootNode, "properties", "algorithm")
	if err != nil {
		return nil, fmt.Errorf("scaffolding algorithm: %w", err)
	}

	groupItems, err := r.navigate(rootNode, "properties", "testGroups", "items")
	if err != nil {
		return nil, fmt.Errorf("locating testGroups.items: %w", err)
	}
	groupTemplate, err := r.scaffoldObject(groupItems, map[string]bool{"tests": true})
	if err != nil {
		return nil, fmt.Errorf("scaffolding group template: %w", err)
	}

	testItems, err := r.navigate(groupItems, "properties", "tests", "items")
	if err != nil {
		return nil, fmt.Errorf("locating tests.items: %w", err)
	}
	test, err := r.scaffoldObject(testItems, map[string]bool{"tcId": true})
	if err != nil {
		return nil, fmt.Errorf("scaffolding test: %w", err)
	}
	testEnc, err := json.Marshal(&test)
	if err != nil {
		return nil, err
	}

	envelope := RawObject{
		{Name: "algorithm", Value: algorithm},
		{Name: "schema", Value: mustMarshal(schemaName)},
	}
	if topRequired(root)["header"] {
		envelope = append(envelope, ObjectMember[jsontext.Value]{
			Name: "header", Value: jsontext.Value(`["<header line>"]`),
		})
	}

	groupEnc, err := json.Marshal(&groupTemplate)
	if err != nil {
		return nil, err
	}

	envelope = append(envelope,
		ObjectMember[jsontext.Value]{Name: "groupTemplate", Value: groupEnc},
		ObjectMember[jsontext.Value]{Name: "tests", Value: mustMarshalArray([]jsontext.Value{testEnc})},
		ObjectMember[jsontext.Value]{Name: "notes", Value: emptyObject()},
	)
	encoded, err := json.Marshal(&envelope)
	if err != nil {
		return nil, err
	}

	return FormatBytes(encoded)
}

// scaffoldObject walks the property declarations of node.obj and emits an
// ordered object of placeholder values, skipping any keys named in skip.
func (r *schemaResolver) scaffoldObject(node schemaNode, skip map[string]bool) (RawObject, error) {
	propsVal, ok := node.obj.Get("properties")
	if !ok {
		return RawObject{}, nil
	}
	props, err := parseObject(propsVal)
	if err != nil {
		return nil, fmt.Errorf("parsing properties: %w", err)
	}

	out := RawObject{}
	for _, m := range props {
		if skip[m.Name] {
			continue
		}
		spec, err := parseObject(m.Value)
		if err != nil {
			return nil, fmt.Errorf("property %q: %w", m.Name, err)
		}

		value, err := r.placeholderValue(schemaNode{obj: spec, root: node.root}, m.Name)
		if err != nil {
			return nil, fmt.Errorf("property %q: %w", m.Name, err)
		}

		out = append(out, ObjectMember[jsontext.Value]{Name: m.Name, Value: value})
	}
	return out, nil
}

// placeholderValue chooses a typed placeholder for a single property based
// on its schema spec (enum, $ref, type, format).
func (r *schemaResolver) placeholderValue(node schemaNode, name string) (jsontext.Value, error) {
	if refVal, ok := node.obj.Get("$ref"); ok {
		return r.placeholderForRef(node, name, refVal)
	}
	if enumVal, ok := node.obj.Get("enum"); ok {
		return placeholderForEnum(enumVal)
	}

	typeStr := decodeStringOr(node.obj, "type", "")
	switch typeStr {
	case "string":
		format := decodeStringOr(node.obj, "format", "")
		if format != "" {
			return mustMarshal(fmt.Sprintf("<%s>", format)), nil
		}
		return mustMarshal(fmt.Sprintf("<%s>", name)), nil
	case "integer", "number":
		return jsontext.Value("0"), nil
	case "boolean":
		return jsontext.Value("false"), nil
	case "array":
		// One placeholder element if we can derive its type, otherwise empty.
		if items, ok := node.obj.Get("items"); ok {
			itemSpec, err := parseObject(items)
			if err == nil {
				// Strip a trailing "s" from the field name so an array
				// called "flags" yields placeholder "<flag>" rather than
				// "<flags>".
				itemName := strings.TrimSuffix(name, "s")
				elem, err := r.placeholderValue(schemaNode{obj: itemSpec, root: node.root}, itemName)
				if err == nil {
					return mustMarshalArray([]jsontext.Value{elem}), nil
				}
			}
		}
		return jsontext.Value("[]"), nil
	case "object", "":
		// Recurse one level into known-shape sub-objects.
		obj, err := r.scaffoldObject(node, nil)
		if err != nil {
			return nil, err
		}
		enc, err := json.Marshal(&obj)
		if err != nil {
			return nil, err
		}
		return enc, nil
	default:
		return mustMarshal(fmt.Sprintf("<%s>", typeStr)), nil
	}
}

// placeholderForRef resolves a $ref (same-doc or cross-doc) and emits a
// placeholder for the dereferenced schema. Two specific common.json refs
// (Source, Result) are short-circuited to operator-friendly placeholders;
// all other refs are followed via the resolver.
func (r *schemaResolver) placeholderForRef(node schemaNode, name string, refVal jsontext.Value) (jsontext.Value, error) {
	var ref string
	if err := json.Unmarshal(refVal, &ref); err != nil {
		return nil, fmt.Errorf("decoding $ref: %w", err)
	}
	switch ref {
	case "common.json#/definitions/Source":
		return jsontext.Value(`{"name": "<source name>", "version": "<version>"}`), nil
	case "common.json#/definitions/Result":
		return mustMarshal("<one of: valid, invalid, acceptable>"), nil
	}

	resolved, err := r.resolve(node)
	if err != nil {
		// Cross-document ref we can't resolve; emit an opaque placeholder so
		// the operator can fill it in by hand.
		return mustMarshal(fmt.Sprintf("<%s>", ref)), nil
	}

	return r.placeholderValue(resolved, name)
}

// placeholderForEnum returns the enum's value if there's only one (e.g. a
// fixed type discriminator), otherwise an angle-bracket hint listing all
// allowed values.
func placeholderForEnum(enumVal jsontext.Value) (jsontext.Value, error) {
	var values []any
	if err := json.Unmarshal(enumVal, &values); err != nil {
		return nil, fmt.Errorf("decoding enum: %w", err)
	}
	if len(values) == 1 {
		return mustMarshal(values[0]), nil
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%v", v)
	}

	return mustMarshal(fmt.Sprintf("<one of: %s>", strings.Join(parts, ", "))), nil
}

// scalarPlaceholder returns a placeholder for a single scalar property
// located at the given path beneath node.
func (r *schemaResolver) scalarPlaceholder(node schemaNode, path ...string) (jsontext.Value, error) {
	spec, err := r.navigate(node, path...)
	if err != nil {
		return nil, err
	}

	return r.placeholderValue(spec, path[len(path)-1])
}

// topRequired returns the set of names in the schema's top-level required
// array. Returns nil if the schema doesn't declare one (callers treat nil
// like an empty set).
func topRequired(root RawObject) map[string]bool {
	requiredVal, ok := root.Get("required")
	if !ok {
		return nil
	}

	var names []string
	if err := json.Unmarshal(requiredVal, &names); err != nil {
		return nil
	}

	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}

	return out
}

// decodeStringOr reads a string-valued field from obj, returning fallback if
// the field is absent or not a string.
func decodeStringOr(obj RawObject, name, fallback string) string {
	v, ok := obj.Get(name)
	if !ok {
		return fallback
	}

	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return fallback
	}

	return s
}
