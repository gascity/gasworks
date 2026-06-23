package sts

import "encoding/json"

// remarshal converts httpc's parsed JSON value (an `any`) into a typed struct by round-tripping
// through JSON. httpc already decoded the bytes into generic Go values; re-encoding and decoding
// into the target struct is the simplest faithful mapping and tolerates extra server fields.
func remarshal(body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
