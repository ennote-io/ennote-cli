// Package kvtext parses key/value text into a flat string map.
package kvtext

import (
	"encoding/json"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/validation"
)

// ParseDotenv reads a dotenv document: `KEY=VALUE` lines, optional `export`
// prefix, `#` comments, one optional layer of quotes. Keys must be
// shell-variable names, so JSON, YAML and prose yield no pairs.
func ParseDotenv(raw string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := splitPair(line, "=")
		if !ok || !validation.IsEnvName(key) {
			continue
		}
		kv[key] = value
	}
	return kv
}

// Parse reads a JSON object, or `key=value` / `key: value` lines split on
// whichever delimiter comes first. Values are strings; JSON objects and arrays
// become compact JSON strings. YAML is not attempted: its scalar resolution
// rewrites values ("011" -> "9").
func Parse(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}
	}

	if kv, ok := parseJSON(raw); ok {
		return kv
	}
	return parseLines(raw)
}

func parseJSON(raw string) (map[string]string, bool) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "{") {
		return nil, false
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, false
	}

	kv := make(map[string]string, len(decoded))
	for k, v := range decoded {
		if key := strings.TrimSpace(k); key != "" {
			kv[key] = importers.FlattenValue(v)
		}
	}
	return kv, len(kv) > 0
}

// parseLines splits each line on its first `=` or `:`, whichever comes first,
// so neither delimiter hijacks the other's lines. Lines without one are dropped.
func parseLines(raw string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		delim := "="
		if eq, colon := strings.Index(line, "="), strings.Index(line, ":"); eq < 0 || (colon >= 0 && colon < eq) {
			delim = ":"
		}
		key, value, ok := splitPair(line, delim)
		if !ok {
			continue
		}
		kv[key] = value
	}
	return kv
}

// splitPair splits one line, skipping blanks and `#` comments and stripping one
// layer of quotes from the value.
func splitPair(line, delim string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	key, value, found := strings.Cut(line, delim)
	if !found {
		return "", "", false
	}

	key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
	if key == "" {
		return "", "", false
	}

	return key, unquote(strings.TrimSpace(value)), true
}

func unquote(value string) string {
	if len(value) >= 2 {
		if q := value[0]; (q == '"' || q == '\'') && value[len(value)-1] == q {
			return value[1 : len(value)-1]
		}
	}
	return value
}
