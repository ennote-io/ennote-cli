package importers

import "strings"

// MatchesScope reports whether a vault, folder or grouping name satisfies a
// --vault filter, and is the one definition of that match for every provider.
// An empty filter matches everything. Matching is case-insensitive, treats "/"
// and "\" alike, ignores a trailing slash on the filter, and honors segment
// boundaries: "Dev" and "Dev/" match "Dev/Cloud" but never "Development".
func MatchesScope(candidate, filter string) bool {
	if filter == "" {
		return true
	}
	if candidate == "" {
		return false
	}
	normCandidate := strings.ToLower(strings.ReplaceAll(candidate, "\\", "/"))
	normFilter := strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(filter, "\\", "/")), "/")

	if normCandidate == normFilter {
		return true
	}

	return strings.HasPrefix(normCandidate, normFilter+"/")
}
