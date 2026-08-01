// Package artifactapi is the generated typed client for the vendored Beads API
// contract. Its current consumer is the Observer artifact-content uploader.
//
// Direction is contract-first: contracts/beadsapi/v1/openapi.bundled.json is a
// byte-locked OpenAPI 3.1.1 source. generate.go mechanically lowers the supported
// 3.1 constructs for the pinned OpenAPI 3.0 generator, then emits the complete
// 39-operation ClientWithResponses. Do not hand-edit client.gen.go.
//
// The generator executable is pinned and invoked only by go generate; it is not
// part of the module or the Observer binary dependency closure.
//
//go:generate go run generate.go
package artifactapi
