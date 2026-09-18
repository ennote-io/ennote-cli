package csvutil

import (
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

// Row is a single CSV record with case-insensitive column access.
type Row struct {
	// Line is the 1-based line number of the record in the source file.
	Line int

	cols   map[string]int
	record []string
}

// Get returns the trimmed value of the named column, or "" when the column is
// absent or the record is short.
func (r *Row) Get(key string) string {
	idx, ok := r.cols[strings.ToLower(key)]
	if !ok || idx < 0 || idx >= len(r.record) {
		return ""
	}
	return strings.TrimSpace(r.record[idx])
}

// First returns the value of the first listed column that carries one, or ""
// when none do.
func (r *Row) First(keys ...string) string {
	for _, key := range keys {
		if v := r.Get(key); v != "" {
			return v
		}
	}
	return ""
}

// SplitLabels parses a label or tag column, accepting comma- and
// semicolon-separated lists. It returns nil when raw holds no label.
func SplitLabels(raw string) []string {
	if raw == "" {
		return nil
	}

	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' })
	labels := make([]string, 0, len(fields))
	for _, f := range fields {
		if label := strings.TrimSpace(f); label != "" {
			labels = append(labels, label)
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// IsEmpty reports whether every field in the record is blank.
func (r *Row) IsEmpty() bool {
	return allBlank(r.record)
}

// Has reports whether the named column holds a non-empty value.
func (r *Row) Has(key string) bool {
	return r.Get(key) != ""
}

// MatchesVault reports whether the row's folder column satisfies filter, using
// importers.MatchesScope.
func (r *Row) MatchesVault(folderKey, filter string) bool {
	return importers.MatchesScope(r.Get(folderKey), filter)
}
