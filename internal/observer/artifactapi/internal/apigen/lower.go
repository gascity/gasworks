// Package apigen contains build-time-only transformations for the vendored API.
// It is not imported by the Observer runtime.
package apigen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// GeneratorTargetVersion is the OpenAPI dialect accepted by the pinned
// oapi-codegen/kin-openapi generator. The published contract remains 3.1.1.
const GeneratorTargetVersion = "3.0.3"

// Lower mechanically rewrites the supported OpenAPI 3.1 constructs in the
// frozen bundle into their OpenAPI 3.0 equivalents. It is deliberately not a
// general downgrader: an unsupported construct fails generation instead of
// silently changing the client contract.
func Lower(bundled []byte) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(bundled, &root); err != nil {
		return nil, fmt.Errorf("lower artifact API: %w", err)
	}

	root["openapi"] = GeneratorTargetVersion
	if info, ok := root["info"].(map[string]any); ok {
		delete(info, "summary")
	}
	root["x-gasworks-generator-view"] = map[string]any{
		"generated": true,
		"note":      "Mechanical OpenAPI 3.0.3 lowering for oapi-codegen; not the published contract",
	}

	var unsupported []string
	lowerNode(root, "", &unsupported)
	if len(unsupported) > 0 {
		sort.Strings(unsupported)
		return nil, fmt.Errorf("lower artifact API: unsupported OpenAPI 3.1 construct(s): %v", unsupported)
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("lower artifact API: encode: %w", err)
	}
	return out.Bytes(), nil
}

func lowerNode(node any, path string, unsupported *[]string) {
	switch value := node.(type) {
	case map[string]any:
		if raw, ok := value["type"]; ok {
			if list, isList := raw.([]any); isList {
				var types []string
				nullable := false
				for _, item := range list {
					typeName, _ := item.(string)
					if typeName == "null" {
						nullable = true
						continue
					}
					types = append(types, typeName)
				}
				switch len(types) {
				case 0:
					delete(value, "type")
				case 1:
					value["type"] = types[0]
				default:
					*unsupported = append(*unsupported,
						fmt.Sprintf("%s: multi-type union %v is not expressible in OpenAPI 3.0", path, types))
				}
				if nullable {
					value["nullable"] = true
				}
			}
		}

		// A null branch around one reference becomes nullable + allOf. A sibling
		// next to a $ref would be ignored by OpenAPI 3.0, hence the wrapper.
		for _, keyword := range []string{"oneOf", "anyOf"} {
			branches, ok := value[keyword].([]any)
			if !ok {
				continue
			}
			kept := make([]any, 0, len(branches))
			sawNull := false
			for _, branch := range branches {
				if object, isObject := branch.(map[string]any); isObject && len(object) == 1 && object["type"] == "null" {
					sawNull = true
					continue
				}
				kept = append(kept, branch)
			}
			if !sawNull {
				continue
			}
			value["nullable"] = true
			if len(kept) == 1 {
				delete(value, keyword)
				value["allOf"] = kept
			} else {
				value[keyword] = kept
			}
		}

		if value["type"] == "null" {
			delete(value, "type")
			value["nullable"] = true
		}

		if encoding, ok := value["contentEncoding"].(string); ok {
			switch encoding {
			case "binary":
				value["format"] = "binary"
			case "base64":
				value["format"] = "byte"
			default:
				*unsupported = append(*unsupported,
					fmt.Sprintf("%s.contentEncoding: %q has no OpenAPI 3.0 format", path, encoding))
			}
			delete(value, "contentEncoding")
		}

		for _, key := range sortedKeys(value) {
			if key == "$defs" || key == "contentMediaType" {
				*unsupported = append(*unsupported, fmt.Sprintf("%s.%s: 3.1-only keyword", path, key))
			}
			lowerNode(value[key], path+"."+key, unsupported)
		}
	case []any:
		for index, item := range value {
			lowerNode(item, fmt.Sprintf("%s[%d]", path, index), unsupported)
		}
	}
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
