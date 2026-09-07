package importers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// GetImporter resolves an Importer based on the requested format and file inspection.
func GetImporter(format Format, r io.ReaderAt, size int64, filePath string) (Importer, error) {
	resolvedFormat := format
	if resolvedFormat == "" || resolvedFormat == FormatAuto {
		var err error
		resolvedFormat, err = DetectFormat(r, size, filePath)
		if err != nil {
			return nil, err
		}
	}

	switch resolvedFormat {
	case Format1PUX:
		return New1PUXImporter(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, resolvedFormat)
	}
}

// DetectFormat inspects the file extension, ZIP metadata, or JSON root keys to determine format.
func DetectFormat(r io.ReaderAt, size int64, filePath string) (Format, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".1pux" {
		return Format1PUX, nil
	}

	// Inspect first bytes for ZIP header
	header := make([]byte, 4)
	if _, err := r.ReadAt(header, 0); err == nil && bytes.Equal(header, []byte("PK\x03\x04")) {
		zipReader, err := zip.NewReader(r, size)
		if err == nil {
			for _, file := range zipReader.File {
				if file.Name == "export.attributes" || file.Name == "export.data" {
					return Format1PUX, nil
				}
			}
		}
	}

	// Inspect JSON content (first 4KB)
	peekLen := int64(4096)
	if size < peekLen {
		peekLen = size
	}
	peekBuf := make([]byte, peekLen)
	if _, err := r.ReadAt(peekBuf, 0); err == nil {
		var partialMap map[string]interface{}
		if err := json.Unmarshal(peekBuf, &partialMap); err == nil {
			if _, hasAccounts := partialMap["accounts"]; hasAccounts {
				return Format1PUX, nil
			}
		}
	}

	return "", fmt.Errorf("%w: could not auto-detect format for %s", ErrUnsupportedFormat, filepath.Base(filePath))
}
