package importers

import (
	"encoding/json"
	"testing"
)

func decodeKeysValues(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	var decoded map[string]map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not a flat string map: %v (payload=%s)", err, payload)
	}
	return decoded["keysValues"]
}

func TestBuildKeysValues_FlatStringMap(t *testing.T) {
	kv := map[string]string{
		"API_TOKEN": "abc123",
		"CONFIG":    FlattenValue(map[string]any{"retries": float64(3)}),
		"HOSTS":     FlattenValue([]any{"a", "b"}),
		"DEBUG":     FlattenValue(true),
	}

	payload, warnings, err := BuildKeysValues("Service Config", kv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for env-safe keys, got %v", warnings)
	}

	got := decodeKeysValues(t, payload)
	want := map[string]string{
		"API_TOKEN": "abc123",
		"CONFIG":    `{"retries":3}`,
		"HOSTS":     `["a","b"]`,
		"DEBUG":     "true",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: expected %q, got %q", k, v, got[k])
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected %d keys, got %d: %+v", len(want), len(got), got)
	}
}

func TestBuildKeysValues_ShellUnsafeKeysPreservedSilently(t *testing.T) {
	kv := map[string]string{
		"home address": "123 Main St, Springfield, IL",
		"first name":   "John",
		"TOKEN":        "abc",
	}

	payload, warnings, err := BuildKeysValues("Test Identity", kv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := decodeKeysValues(t, payload)
	if got["home address"] != "123 Main St, Springfield, IL" {
		t.Errorf("expected 'home address' preserved verbatim, got %+v", got)
	}
	if got["first name"] != "John" {
		t.Errorf("expected 'first name' preserved verbatim, got %+v", got)
	}
	if _, renamed := got["home_address"]; renamed {
		t.Errorf("key was renamed: %+v", got)
	}

	// Keys a shell cannot expand still import cleanly: nothing was dropped or
	// rewritten, so there is nothing to report.
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for a clean import, got %v", warnings)
	}
}

func TestBuildKeysValues_DropsEmptyKeys(t *testing.T) {
	kv := map[string]string{
		"":      "orphan",
		"   ":   "whitespace",
		"TOKEN": "abc",
	}

	payload, warnings, err := BuildKeysValues("Broken Notes", kv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := decodeKeysValues(t, payload)
	if len(got) != 1 || got["TOKEN"] != "abc" {
		t.Errorf("expected only TOKEN to survive, got %+v", got)
	}

	want := `"Broken Notes": dropped 2 value(s) with an empty key`
	if len(warnings) != 1 || warnings[0] != want {
		t.Errorf("expected warning %q, got %v", want, warnings)
	}
}

func TestBuildKeysValues_DuplicateAfterTrimKeepsFirst(t *testing.T) {
	kv := map[string]string{
		"TOKEN":  "first",
		"TOKEN ": "second",
	}

	payload, warnings, err := BuildKeysValues("Api Keys", kv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := decodeKeysValues(t, payload)
	if len(got) != 1 || got["TOKEN"] != "first" {
		t.Errorf("expected first value to win, got %+v", got)
	}

	want := `"Api Keys": duplicate key "TOKEN", keeping the first value`
	if len(warnings) != 1 || warnings[0] != want {
		t.Errorf("expected warning %q, got %v", want, warnings)
	}
}

func TestFlattenValue(t *testing.T) {
	cases := []struct {
		name  string
		input any
		want  string
	}{
		{"nil", nil, ""},
		{"string", "plain", "plain"},
		{"bool", false, "false"},
		{"integral float", float64(5432), "5432"},
		{"fractional float", 1.5, "1.5"},
		{"json number", json.Number("42"), "42"},
		{"nested map", map[string]any{"b": "2", "a": map[string]any{"c": true}}, `{"a":{"c":true},"b":"2"}`},
		{"slice", []any{1.0, "two", nil}, `[1,"two",null]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FlattenValue(tc.input); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
