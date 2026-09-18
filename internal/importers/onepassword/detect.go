package onepassword

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

var _ importers.FileDetector = (*PUXImporter)(nil)

// puxJSONPeek is how much of a raw export.data document is read to look for its
// top-level keys.
const puxJSONPeek = 4096

// MatchFile reports whether the export is a 1PUX archive or a raw export.data
// JSON document: the .1pux extension, zip members, or a top-level "accounts"
// key.
func (p *PUXImporter) MatchFile(r io.ReaderAt, size int64, name string) bool {
	if strings.EqualFold(filepath.Ext(name), ".1pux") {
		return true
	}
	return isPUXArchive(r, size) || isPUXJSON(r, size)
}

// isPUXArchive reports whether r is a zip holding 1PUX export members.
func isPUXArchive(r io.ReaderAt, size int64) bool {
	header := make([]byte, 4)
	if _, err := r.ReadAt(header, 0); err != nil || !bytes.Equal(header, []byte("PK\x03\x04")) {
		return false
	}

	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return false
	}
	for _, file := range zipReader.File {
		if file.Name == "export.attributes" || file.Name == "export.data" {
			return true
		}
	}
	return false
}

// isPUXJSON reports whether r looks like a raw 1PUX export.data JSON document.
func isPUXJSON(r io.ReaderAt, size int64) bool {
	buf := make([]byte, min(size, puxJSONPeek))
	if _, err := r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(buf))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}

	// Scan only top-level keys; the peek window usually truncates the document,
	// so decoding the whole object is not an option.
	for depth := 0; ; {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch typed := token.(type) {
		case json.Delim:
			if typed == '{' || typed == '[' {
				depth++
			} else {
				depth--
			}
		case string:
			if depth == 0 && typed == "accounts" {
				return true
			}
		}
	}
}
