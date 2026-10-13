package lastpass

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

// CSVImporter maps rows of a LastPass CSV export onto normalized secrets.
type CSVImporter struct{}

// NewCSVImporter creates a new LastPass CSV importer.
func NewCSVImporter() *CSVImporter {
	return &CSVImporter{}
}

// ProviderName identifies the resolved source format for CLI output.
func (p *CSVImporter) ProviderName() string {
	return "LastPass CSV"
}

// MatchHeaders reports whether headers carry LastPass's signature: grouping plus name.
func (p *CSVImporter) MatchHeaders(headers []string) bool {
	present := csvutil.HeaderSet(headers)
	return present["grouping"] && present["name"]
}

// Parse streams the CSV, filtering by vault if requested and skipping unusable
// rows with a warning rather than aborting the import.
func (p *CSVImporter) Parse(r io.ReaderAt, size int64, opts importers.ImportOptions) (*importers.ImportResult, error) {
	result := &importers.ImportResult{}

	err := csvutil.ForEachRow(r, size, func(row *csvutil.Row) error {
		if opts.VaultFilter != "" && !row.MatchesVault("grouping", opts.VaultFilter) {
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

// normalizeRow yields the row's primary secret plus a companion 2FA secret when
// the totp column holds a usable value. A row whose content maps to no secret
// is reported.
func (p *CSVImporter) normalizeRow(row *csvutil.Row) ([]importers.ImportedSecret, []string) {
	if row.IsEmpty() {
		return nil, nil
	}

	title := row.Get("name")
	if title == "" {
		title = "Untitled Secret"
	}

	rawTOTP := row.Get("totp")
	base := importers.ImportedSecret{
		Name:   title,
		URL:    rowURL(row),
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
// and returns nil when the row carries neither credentials nor note text.
func primary(row *csvutil.Row, base importers.ImportedSecret) (*importers.ImportedSecret, []string, error) {
	extra := row.Get("extra")

	var (
		payload  []byte
		warnings []string
		err      error
	)

	switch {
	case row.Has("username") || row.Has("password"):
		// A login's free-form text shares the column a note uses for its body.
		base.Type, base.Notes = importers.TypeLoginPassword, extra
		payload, err = json.Marshal(map[string]string{
			"login":    row.Get("username"),
			"password": row.Get("password"),
		})

	case strings.HasPrefix(extra, "NoteType:"):
		base.Type, payload, warnings, err = notePayload(base.Name, extra)

	case extra != "":
		base.Type = importers.TypeSecurityNotes
		payload, err = securityNotesPayload(extra)
	}

	if err != nil || payload == nil {
		return nil, warnings, err
	}

	base.Payload = payload
	return &base, warnings, nil
}

// notePayload encodes a structured LastPass note: a NoteType block that yields
// key/value pairs becomes KEYS_VALUES, anything else stays SECURITY_NOTES.
func notePayload(title, extra string) (importers.SecretType, []byte, []string, error) {
	// LastPass closes every NoteType block with a free-form Notes field.
	kv := kvtext.ParseWithTerminalKey(extra, "notes")
	if len(kv) == 0 {
		payload, err := securityNotesPayload(extra)
		return importers.TypeSecurityNotes, payload, nil, err
	}

	payload, warnings, err := importers.BuildKeysValues(title, kv)
	return importers.TypeKeysValues, payload, warnings, err
}

func securityNotesPayload(extra string) ([]byte, error) {
	return json.Marshal(map[string]string{"securityNotes": extra})
}

// rowURL returns the row's url column, dropping the placeholder LastPass writes
// for secure notes.
func rowURL(row *csvutil.Row) string {
	u := row.Get("url")
	if isNoteSentinel(u) || !validation.IsValidEndpoint(u) {
		return ""
	}
	return u
}

// rowLabels turns the row's grouping and favorite flag into labels.
func rowLabels(row *csvutil.Row) []string {
	var labels []string
	if grouping := row.Get("grouping"); grouping != "" {
		labels = append(labels, grouping)
	}
	if csvutil.Truthy(row.Get("fav")) {
		labels = append(labels, "favorite")
	}
	return labels
}

// isNoteSentinel reports whether u is LastPass's placeholder URL for secure notes.
func isNoteSentinel(u string) bool {
	return strings.EqualFold(u, "http://sn") || strings.EqualFold(u, "https://sn")
}
