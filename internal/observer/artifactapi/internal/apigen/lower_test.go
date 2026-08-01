package apigen

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLowerConvertsOnlySupportedOpenAPI31Constructs(t *testing.T) {
	source := []byte(`{
  "openapi": "3.1.1",
  "info": {"title":"test","version":"1","summary":"3.1 only"},
  "components": {"schemas": {
    "MaybeText": {"type":["string","null"]},
    "MaybeRef": {"oneOf":[{"$ref":"#/components/schemas/MaybeText"},{"type":"null"}]},
    "Binary": {"type":"string","contentEncoding":"binary"},
    "Base64": {"type":"string","contentEncoding":"base64"}
  }}
}`)

	got, err := Lower(source)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("decode lowered document: %v", err)
	}
	if doc["openapi"] != GeneratorTargetVersion {
		t.Fatalf("openapi = %v, want %s", doc["openapi"], GeneratorTargetVersion)
	}
	info := doc["info"].(map[string]any)
	if _, ok := info["summary"]; ok {
		t.Fatal("3.1 info.summary survived lowering")
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	maybeText := schemas["MaybeText"].(map[string]any)
	if maybeText["type"] != "string" || maybeText["nullable"] != true {
		t.Fatalf("MaybeText = %#v", maybeText)
	}
	maybeRef := schemas["MaybeRef"].(map[string]any)
	if maybeRef["nullable"] != true || len(maybeRef["allOf"].([]any)) != 1 {
		t.Fatalf("MaybeRef = %#v", maybeRef)
	}
	if binary := schemas["Binary"].(map[string]any); binary["format"] != "binary" {
		t.Fatalf("Binary = %#v", binary)
	}
	if base64 := schemas["Base64"].(map[string]any); base64["format"] != "byte" {
		t.Fatalf("Base64 = %#v", base64)
	}
	if !strings.HasSuffix(string(got), "\n") {
		t.Fatal("lowered document must have one deterministic trailing newline")
	}
	again, err := Lower(source)
	if err != nil {
		t.Fatalf("second Lower: %v", err)
	}
	if string(got) != string(again) {
		t.Fatal("lowering the same bytes twice was not deterministic")
	}
}

func TestLowerRejectsUnsupportedOpenAPI31Constructs(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{name: "multi type", schema: `{"type":["string","integer"]}`, want: "multi-type union"},
		{name: "defs", schema: `{"$defs":{"x":{"type":"string"}}}`, want: "$defs"},
		{name: "media type", schema: `{"type":"string","contentMediaType":"text/plain"}`, want: "contentMediaType"},
		{name: "encoding", schema: `{"type":"string","contentEncoding":"gzip"}`, want: `contentEncoding: "gzip"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := []byte(`{"openapi":"3.1.1","info":{"title":"t","version":"1"},"components":{"schemas":{"S":` + tt.schema + `}}}`)
			_, err := Lower(source)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Lower error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
