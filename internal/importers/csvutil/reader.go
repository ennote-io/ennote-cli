package csvutil

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

// utf8BOM is the byte order mark Excel and several password managers prepend to
// their exports.
const utf8BOM = "\xEF\xBB\xBF"

// comma is the only delimiter read; other separators are not detected.
const comma = ','

// NewReader returns a csv.Reader over the export at r: a leading UTF-8 BOM is
// stripped, and ragged or lazily quoted records are accepted.
//
// Records share one backing slice, so callers must copy values they retain.
// Empty input returns importers.ErrEmptyExport.
func NewReader(r io.ReaderAt, size int64) (*csv.Reader, error) {
	offset, err := bomOffset(r, size)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(io.NewSectionReader(r, offset, size-offset))
	reader.Comma = comma
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.ReuseRecord = true
	return reader, nil
}

// bomOffset reports the byte offset the CSV body starts at, past any UTF-8 BOM.
func bomOffset(r io.ReaderAt, size int64) (int64, error) {
	if size <= 0 {
		return 0, importers.ErrEmptyExport
	}
	if size < int64(len(utf8BOM)) {
		return 0, nil
	}

	var prefix [len(utf8BOM)]byte
	if _, err := r.ReadAt(prefix[:], 0); err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("failed to read CSV header: %w", err)
	}
	if string(prefix[:]) == utf8BOM {
		return int64(len(utf8BOM)), nil
	}
	return 0, nil
}

// ReadHeader returns the header row of a CSV file, trimmed and lower-cased.
// Empty or whitespace-only input returns importers.ErrEmptyExport.
func ReadHeader(r io.ReaderAt, size int64) ([]string, error) {
	reader, err := NewReader(r, size)
	if err != nil {
		return nil, err
	}

	record, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, importers.ErrEmptyExport
		}
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}
	if allBlank(record) {
		return nil, importers.ErrEmptyExport
	}

	headers := make([]string, len(record))
	for i, h := range record {
		headers[i] = normalizeKey(h)
	}
	return headers, nil
}

// HeaderSet indexes a header row for membership tests, normalizing keys as
// ReadHeader and Row.Get do.
func HeaderSet(headers []string) map[string]bool {
	present := make(map[string]bool, len(headers))
	for _, h := range headers {
		present[normalizeKey(h)] = true
	}
	return present
}

// ForEachRow streams a CSV export, invoking handler once per data record.
// Handler errors abort the scan and are returned unwrapped. Empty or
// whitespace-only input returns importers.ErrEmptyExport.
func ForEachRow(r io.ReaderAt, size int64, handler func(row *Row) error) error {
	reader, err := NewReader(r, size)
	if err != nil {
		return err
	}

	headers, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return importers.ErrEmptyExport
		}
		return fmt.Errorf("failed to read CSV header: %w", err)
	}
	if allBlank(headers) {
		return importers.ErrEmptyExport
	}

	cols := make(map[string]int, len(headers))
	for i, h := range headers {
		cols[normalizeKey(h)] = i
	}

	// ReuseRecord overwrites one backing slice per Read, so the row copies each
	// record. Handlers may retain the strings Get returns, but not the *Row.
	row := &Row{cols: cols}
	line := 1
	for {
		line++
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("csv read error on line %d: %w", line, err)
		}

		row.Line = line
		row.record = append(row.record[:0], record...)

		if err := handler(row); err != nil {
			return err
		}
	}
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// allBlank reports whether every field is empty or whitespace.
func allBlank(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}
