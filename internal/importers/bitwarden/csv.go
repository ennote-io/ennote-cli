package bitwarden

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/importers/csvutil"
	"github.com/ennote-io/ennote-cli/internal/validation"
)

var _ importers.Provider = (*CSVImporter)(nil)

// CSVImporter maps rows of a Bitwarden CSV export onto normalized secrets.
type CSVImporter struct{}

// NewCSVImporter creates a new Bitwarden CSV importer.
func NewCSVImporter() *CSVImporter {
	return &CSVImporter{}
}

// ProviderName identifies the resolved source format for CLI output.
func (p *CSVImporter) ProviderName() string {
	return "Bitwarden CSV"
}

// SupportsVaultFilter reports whether Bitwarden CSV exports carry vault or
// folder information.
func (p *CSVImporter) SupportsVaultFilter() bool {
	return true
}

// MatchHeaders reports whether headers carry Bitwarden's signature: either a
// folder or collections column, a login_username or login_password column, and
// item name, without LastPass's grouping column. The login_ credential columns
// are required because they are present in every real export, unlike login_uri,
// login_totp or reprompt, which a hand-edited file could share with other tools.
func (p *CSVImporter) MatchHeaders(headers []string) bool {
	present := csvutil.HeaderSet(headers)

	// Disqualify other managers (e.g. LastPass)
	if present["grouping"] {
		return false
	}

	hasScope := present["folder"] || present["collections"]
	hasCredentials := present["login_username"] || present["login_password"]

	return hasScope && hasCredentials && present["name"]
}

// Parse streams the CSV, filtering by vault if requested and skipping unusable
// rows with a warning rather than aborting the import.
func (p *CSVImporter) Parse(r io.ReaderAt, size int64, opts importers.ImportOptions) (*importers.ImportResult, error) {
	result := &importers.ImportResult{}

	err := csvutil.ForEachRow(r, size, func(row *csvutil.Row) error {
		if opts.VaultFilter != "" && !p.matchesVault(row, opts.VaultFilter) {
			return nil
		}
		if row.IsEmpty() || isCollectionPlaceholder(row) {
			return nil
		}

		secrets, warnings := p.normalizeRow(row)
		result.Warnings = append(result.Warnings, warnings...)
		result.Secrets = append(result.Secrets, secrets...)
		return nil
	})
	if err != nil {
		return result, err
	}
	if len(result.Secrets) == 0 {
		return result, importers.ErrEmptyExport
	}

	return result, nil
}

// matchesVault evaluates whether a row's folder or collections match the scope filter.
func (p *CSVImporter) matchesVault(row *csvutil.Row, filter string) bool {
	if collections := row.Get("collections"); collections != "" {
		for _, col := range csvutil.SplitLabels(collections) {
			if importers.MatchesScope(col, filter) {
				return true
			}
		}
		return false
	}
	return importers.MatchesScope(row.Get("folder"), filter)
}

// isCollectionPlaceholder reports whether the row is an empty collection placeholder
// in an Organization export (scope populated, but name, type, and content columns blank).
func isCollectionPlaceholder(row *csvutil.Row) bool {
	hasScope := row.Has("collections") || row.Has("folder")
	hasContent := row.Has("name") || row.Has("type") || row.Has("notes") ||
		row.Has("fields") || row.Has("login_username") || row.Has("login_password") ||
		row.Has("login_uri") || row.Has("login_totp")
	return hasScope && !hasContent
}

// normalizeRow yields the row's primary secret plus a companion 2FA secret when
// login_totp holds a usable seed. A row whose content maps to no secret is
// reported.
func (p *CSVImporter) normalizeRow(row *csvutil.Row) ([]importers.ImportedSecret, []string) {
	title := row.Get("name")
	if title == "" {
		title = "Untitled Secret"
	}

	rawTOTP := row.Get("login_totp")
	base := importers.ImportedSecret{
		Name:   title,
		URL:    normalizeURL(row.Get("login_uri")),
		Labels: rowLabels(row),
	}

	var secrets []importers.ImportedSecret
	secret, warnings, err := primary(row, base)
	switch {
	case err != nil:
		warnings = append(warnings, fmt.Sprintf("line %d: failed to encode payload for %q: %v", row.Line, title, err))
	case secret != nil:
		secrets = append(secrets, *secret)
	case rawTOTP == "":
		warnings = append(warnings, fmt.Sprintf("line %d: %q has no credentials, notes or 2FA seed, skipped", row.Line, title))
	}

	notes := ""
	if secret != nil {
		notes = secret.Notes
	}

	totp, err := importers.BuildCompanionTOTP(title, rawTOTP, base.URL, notes, base.Labels, len(secrets) > 0)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("line %d: %v", row.Line, err))
	} else if totp != nil {
		secrets = append(secrets, *totp)
	}

	return secrets, warnings
}

// primary completes base with the type and payload the row's content implies,
// and returns nil when the row carries neither credentials nor note text. The
// type column only selects the branch: a declared note never falls back to
// credentials, while a blank or unrecognized type infers from the columns.
func primary(row *csvutil.Row, base importers.ImportedSecret) (*importers.ImportedSecret, []string, error) {
	rawType := row.Get("type")
	kind := strings.ToLower(rawType)
	body := mergeNotesAndFields(row.Get("notes"), row.Get("fields"))
	credentialsAllowed := kind != "note"

	var (
		payload  []byte
		warnings []string
		err      error
	)

	switch {
	case credentialsAllowed && (row.Has("login_username") || row.Has("login_password")):
		base.Type, base.Notes = importers.TypeLoginPassword, body
		payload, err = json.Marshal(map[string]string{
			"login":    row.Get("login_username"),
			"password": row.Get("login_password"),
		})

	case body != "":
		// A note's body lives only in the encrypted payload, never in Notes.
		base.Type = importers.TypeSecurityNotes
		payload, err = json.Marshal(map[string]string{"securityNotes": body})
	}

	if err != nil || payload == nil {
		return nil, warnings, err
	}
	if kind != "" && kind != "login" && kind != "note" {
		warnings = append(warnings, fmt.Sprintf("line %d: unknown type %q, imported as %s", row.Line, rawType, base.Type))
	}

	base.Payload = payload
	return &base, warnings, nil
}

// rowLabels extracts labels from folder or collections, plus favorite.
func rowLabels(row *csvutil.Row) []string {
	var labels []string
	if folder := row.Get("folder"); folder != "" {
		labels = append(labels, folder)
	}
	if collections := row.Get("collections"); collections != "" {
		labels = append(labels, csvutil.SplitLabels(collections)...)
	}
	if csvutil.Truthy(row.Get("favorite")) {
		labels = append(labels, "favorite")
	}
	return labels
}

// normalizeURL takes the first valid endpoint from a comma-separated login_uri list.
func normalizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	for _, part := range strings.Split(raw, ",") {
		u := strings.TrimSpace(part)
		if validation.IsValidEndpoint(u) {
			return u
		}
	}
	return ""
}

// mergeNotesAndFields joins notes and custom fields with a double newline.
func mergeNotesAndFields(notes, fields string) string {
	switch {
	case notes != "" && fields != "":
		return notes + "\n\n" + fields
	case fields != "":
		return fields
	default:
		return notes
	}
}
