package wire

import (
	"fmt"
	"reflect"
	"time"
)

// enumMember is implemented by every generated enum type (oapi-codegen emits a
// value-receiver Valid() on each). We use it to enforce closed-enum membership at
// decode time — the JSON-Schema enum constraint does not run at ingest, and Go's
// json decoder happily unmarshals any string into a named string enum type.
type enumMember interface {
	Valid() bool
}

var (
	timeType = reflect.TypeOf(time.Time{})
	enumType = reflect.TypeOf((*enumMember)(nil)).Elem()
)

// validateEnumMembership walks a strictly-decoded value and calls Valid() on every
// field whose type is a generated enum, returning ErrEnumOutOfRange for the first
// out-of-range value. It skips unexported fields (the union raw-message wrappers) and
// time.Time; nested unions are validated separately via their own decoded shapes.
func validateEnumMembership(v any, path string) error {
	return walkEnums(reflect.ValueOf(v), path)
}

func walkEnums(v reflect.Value, path string) error {
	if !v.IsValid() {
		return nil
	}
	// Dereference pointers/interfaces first: an optional enum is a *EnumType, and the
	// generated Valid() has a value receiver, so calling it through a nil pointer would
	// panic. A nil optional field is simply absent — nothing to check.
	if k := v.Kind(); k == reflect.Pointer || k == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		return walkEnums(v.Elem(), path)
	}
	// Now v is a concrete value. If its type is a generated enum, check membership.
	if v.CanInterface() && v.Type().Implements(enumType) {
		em, _ := v.Interface().(enumMember)
		if !em.Valid() {
			return decodeErr(ErrEnumOutOfRange, path,
				fmt.Sprintf("value %v is not a member of enum %s", v.Interface(), v.Type().Name()), nil)
		}
		return nil
	}
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == timeType {
			return nil
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanInterface() { // unexported (e.g. the union json.RawMessage)
				continue
			}
			name := t.Field(i).Name
			if err := walkEnums(f, joinPath(path, name)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := walkEnums(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := walkEnums(iter.Value(), joinPath(path, "*")); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}
