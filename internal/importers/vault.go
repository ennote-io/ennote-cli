package importers

import "strings"

// MatchesScope reports whether a vault, folder or grouping name satisfies a
// --vault filter, and is the one definition of that match for every provider.
// An empty filter matches everything. Matching is case-insensitive, treats "/"
// and "\" alike, and honors path segment boundaries, so "Dev" matches "Dev" and
// "Dev/Cloud" but never "Development".
func MatchesScope(candidate, filter string) bool {
	if filter == "" {
		return true
	}
	if candidate == "" {
		return false
	}
	if strings.EqualFold(candidate, filter) {
		return true
	}

	normCandidate := strings.ToLower(strings.ReplaceAll(candidate, "\\", "/"))
	normFilter := strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(filter, "\\", "/")), "/")

	return strings.HasPrefix(normCandidate, normFilter+"/")
}
