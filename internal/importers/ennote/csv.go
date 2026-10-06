// Package ennote parses Ennote's native CSV layout. It is also the terminal
// fallback for CSV exports no dedicated provider claims, so its column handling
// is permissive.
package ennote

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/importers/csvutil"
	"github.com/ennote-io/ennote-cli/internal/kvtext"
	"github.com/ennote-io/ennote-cli/internal/validation"
)

var _ importers.Provider = (*CSVImporter)(nil)

// CSVImporter maps rows of an Ennote-shaped CSV onto normalized secrets.
type CSVImporter struct{}

func NewCSVImporter() *CSVImporter {
	return &CSVImporter{}
}

// secretColumns are the columns that may carry secret material; a header row
// needs a name column plus at least one of these to be considered Ennote's own.
var secretColumns = []string{"type", "value", "login", "password", "keys_values", "payload"}

// valueColumns are searched in order for the payload body of a row.
var valueColumns = []string{"value", "keys_values", "payload"}

// ProviderName identifies the resolved source format for CLI output.
func (p *CSVImporter) ProviderName() string {
	return "Ennote CSV"
}

// MatchHeaders reports whether headers name a secret and carry content for it.
func (p *CSVImporter) MatchHeaders(headers []string) bool {
	present := csvutil.HeaderSet(headers)

	if !present["name"] && !present["title"] {
		return false
	}
	for _, col := range secretColumns {
		if present[col] {
			return true
		}
	}
	return false
}

// Parse streams the CSV, skipping unusable rows with a warning rather than
// aborting the import.
func (p *CSVImporter) Parse(r io.ReaderAt, size int64, opts importers.ImportOptions) (*importers.ImportResult, error) {
	result := &importers.ImportResult{}

	err := csvutil.ForEachRow(r, size, func(row *csvutil.Row) error {
		secret, warnings := p.normalizeRow(row)
		result.Warnings = append(result.Warnings, warnings...)
		if secret != nil {
			result.Secrets = append(result.Secrets, *secret)
		}
		return nil
	})
	// Warnings explain why rows were dropped, so they travel with the error.
	if err != nil {
		return result, err
	}
	if len(result.Secrets) == 0 {
		return result, importers.ErrEmptyExport
	}

	return result, nil
}

func (p *CSVImporter) normalizeRow(row *csvutil.Row) (*importers.ImportedSecret, []string) {
	// A delimiter-only line is exporter noise; a row with content that yields
	// no secret is reported below.
	if row.IsEmpty() {
		return nil, nil
	}

	var warnings []string

	name := row.First("name", "title")
	if name == "" {
		name = "Untitled Secret"
	}

	rawType := row.Get("type")
	secretType, known := resolveType(rawType)
	if !known {
		secretType = inferType(row)
		if rawType != "" {
			warnings = append(warnings, fmt.Sprintf("line %d: unknown type %q, imported as %s", row.Line, rawType, secretType))
		}
	}

	value := row.First(valueColumns...)
	notes := row.Get("notes")

	var (
		payload []byte
		err     error
	)

	switch secretType {
	case importers.TypeLoginPassword:
		login := row.First("login", "username")
		password := row.Get("password")
		if login == "" && password == "" {
			break
		}
		payload, err = json.Marshal(map[string]string{
			"login":    login,
			"password": password,
		})

	case importers.TypeKeysValues:
		kv := kvtext.Parse(value)
		if len(kv) == 0 {
			content := fallbackContent(value, notes)
			if content == "" {
				break
			}
			warnings = append(warnings, fmt.Sprintf("line %d: %q holds no key/value pairs, imported as %s", row.Line, name, importers.TypeSecurityNotes))
			secretType = importers.TypeSecurityNotes
			payload, err = json.Marshal(map[string]string{"securityNotes": content})
			break
		}
		kvPayload, kvWarnings, kvErr := importers.BuildKeysValues(name, kv)
		warnings = append(warnings, kvWarnings...)
		payload, err = kvPayload, kvErr

	case importers.TypeSecurityNotes:
		content := fallbackContent(value, notes)
		if content == "" {
			break
		}
		payload, err = json.Marshal(map[string]string{"securityNotes": content})

	case importers.TypeTwoFactor:
		seed, totpErr := importers.ExtractTOTP(row.First("value", "totp"))
		if totpErr != nil {
			return nil, append(warnings, fmt.Sprintf("line %d: invalid 2FA seed for %q: %v, skipped", row.Line, name, totpErr))
		}
		if seed == "" {
			break
		}
		payload, err = json.Marshal(map[string]string{"securityCode": seed})
	}

	if err != nil {
		return nil, append(warnings, fmt.Sprintf("line %d: failed to encode payload for %q: %v", row.Line, name, err))
	}
	if payload == nil {
		return nil, append(warnings, fmt.Sprintf("line %d: %q has no usable %s content, skipped", row.Line, name, secretType))
	}

	targetURL := ""
	if u := row.Get("url"); validation.IsValidEndpoint(u) {
		targetURL = u
	}

	return &importers.ImportedSecret{
		Name:    name,
		Type:    secretType,
		URL:     targetURL,
		Labels:  csvutil.SplitLabels(row.Get("labels")),
		Notes:   notes,
		Payload: payload,
	}, warnings
}

// resolveType matches the documented `--type` names case-insensitively.
func resolveType(raw string) (importers.SecretType, bool) {
	for _, t := range []importers.SecretType{
		importers.TypeLoginPassword,
		importers.TypeSecurityNotes,
		importers.TypeKeysValues,
		importers.TypeTwoFactor,
	} {
		if strings.EqualFold(raw, string(t)) {
			return t, true
		}
	}
	return "", false
}

// inferType derives a type from the columns a row actually fills. TWO_FACTOR is
// never inferred: a bare Base32 string is indistinguishable from a password.
func inferType(row *csvutil.Row) importers.SecretType {
	if row.Has("login") || row.Has("username") || row.Has("password") {
		return importers.TypeLoginPassword
	}
	if value := row.First(valueColumns...); value != "" && len(kvtext.Parse(value)) > 0 {
		return importers.TypeKeysValues
	}
	return importers.TypeSecurityNotes
}

func fallbackContent(value, notes string) string {
	if value != "" {
		return value
	}
	return notes
}
