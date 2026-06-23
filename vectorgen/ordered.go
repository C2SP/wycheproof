package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"
)

// RawObject is an ordered object whose values are raw JSON bytes.
//
// Subtrees stored as jsontext.Value round-trip byte-identical, so we only
// re-emit the keys we explicitly mutate.
type RawObject = OrderedObject[jsontext.Value]

// OrderedObject is an ordered sequence of JSON object members. It implements
// json.MarshalerTo and json.UnmarshalerFrom so it round-trips through
// encoding/json/v2 preserving member order.
//
// Adapted from the example in encoding/json/v2's example_orderedobject_test.go.
type OrderedObject[V any] []ObjectMember[V]

// ObjectMember is a single JSON object member.
type ObjectMember[V any] struct {
	Name  string
	Value V
}

func (obj *OrderedObject[V]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for i := range *obj {
		m := &(*obj)[i]
		if err := json.MarshalEncode(enc, &m.Name); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, &m.Value); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

func (obj *OrderedObject[V]) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if k := dec.PeekKind(); k != '{' {
		return &json.SemanticError{JSONKind: k}
	}
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	for dec.PeekKind() != '}' {
		*obj = append(*obj, ObjectMember[V]{})
		m := &(*obj)[len(*obj)-1]
		if err := json.UnmarshalDecode(dec, &m.Name); err != nil {
			return err
		}
		if err := json.UnmarshalDecode(dec, &m.Value); err != nil {
			return err
		}
	}
	_, err := dec.ReadToken()
	return err
}

// Get returns the value associated with name, or false if absent. On
// duplicate names (allowed by the JSON spec, disallowed by our schemas) the
// first match wins.
func (obj OrderedObject[V]) Get(name string) (V, bool) {
	if i := obj.IndexOf(name); i >= 0 {
		return obj[i].Value, true
	}
	var zero V
	return zero, false
}

// IndexOf returns the position of name in the object, or -1 if absent.
func (obj OrderedObject[V]) IndexOf(name string) int {
	for i := range obj {
		if obj[i].Name == name {
			return i
		}
	}
	return -1
}

// Set replaces the value for name if it exists, or appends a new member if
// not. Returns the (possibly grown) slice.
func (obj OrderedObject[V]) Set(name string, value V) OrderedObject[V] {
	if i := obj.IndexOf(name); i >= 0 {
		obj[i].Value = value
		return obj
	}
	return append(obj, ObjectMember[V]{Name: name, Value: value})
}

// InsertAt inserts a new member at position i. Panics if i is out of range
// (a programmer error; callers are package-internal).
func (obj OrderedObject[V]) InsertAt(i int, name string, value V) OrderedObject[V] {
	return slices.Insert(obj, i, ObjectMember[V]{Name: name, Value: value})
}

// parseObject decodes a JSON object value into an ordered RawObject.
func parseObject(data []byte) (RawObject, error) {
	var obj RawObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("decoding JSON object: %w", err)
	}
	return obj, nil
}

// marshalObject encodes an ordered RawObject, then runs the canonical
// vectorgen formatter so the output matches what FormatFile would write.
func marshalObject(obj RawObject) ([]byte, error) {
	data, err := json.Marshal(&obj)
	if err != nil {
		return nil, fmt.Errorf("encoding JSON object: %w", err)
	}
	return FormatBytes(data)
}
