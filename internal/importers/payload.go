package importers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// BuildKeysValues marshals a KEYS_VALUES payload as {"keysValues": {...}} with a
// flat map[string]string body. Keys are preserved verbatim apart from trimming.
// Empty keys are dropped and duplicates keep the first value; both are warned
// about. Keys a shell cannot expand are kept silently.
func BuildKeysValues(name string, kv map[string]string) ([]byte, []string, error) {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	flat := make(map[string]string, len(kv))
	var warnings []string
	dropped := 0

	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if key == "" {
			dropped++
			continue
		}
		if _, exists := flat[key]; exists {
			warnings = append(warnings, fmt.Sprintf("%q: duplicate key %q, keeping the first value", name, key))
			continue
		}
		flat[key] = kv[raw]
	}

	if dropped > 0 {
		warnings = append(warnings, fmt.Sprintf("%q: dropped %d value(s) with an empty key", name, dropped))
	}

	payload, err := json.Marshal(map[string]map[string]string{"keysValues": flat})
	if err != nil {
		return nil, warnings, fmt.Errorf("failed to serialize keys/values payload for %q: %w", name, err)
	}

	return payload, warnings, nil
}

// FlattenValue renders a decoded JSON value as the string stored in a flat
// KEYS_VALUES map: scalars are formatted, composites become compact JSON. Only
// types json.Marshal would render differently are cased out.
func FlattenValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		// json.Marshal would base64-encode this and silently corrupt the value.
		return string(t)
	case float64:
		// 'f' avoids exponent form: a secret must never render as 1e+21.
		return strconv.FormatFloat(t, 'f', -1, 64)
	}

	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(encoded)
}
