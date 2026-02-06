package cmdutil

import (
	"encoding/json"
	"io"
)

// WriteJSON writes v as JSON to w, followed by a newline.
func WriteJSON(w io.Writer, v any, pretty bool) error {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
