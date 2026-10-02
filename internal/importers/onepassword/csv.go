package onepassword

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/importers/csvutil"
	"github.com/ennote-io/ennote-cli/internal/validation"
)

var _ importers.Provider = (*CSVImporter)(nil)

// CSVImporter maps rows of a 1Password CSV export onto normalized secrets.
type CSVImporter struct{}

func NewCSVImporter() *CSVImporter {
	return &CSVImporter{}
}

// foreignColumns belong to other managers whose exports also carry title and
// password; their presence disqualifies the header.
var foreignColumns = []string{"grouping", "folder"}

// totpColumns are the seed column names across 1Password export generations, in
// resolution order.
var totpColumns = []string{"otp", "otpauth", "one-time password"}

// ProviderName identifies the resolved source format for CLI output.
func (p *CSVImporter) ProviderName() string {
	return "1Password CSV"
}

// MatchHeaders reports whether headers carry 1Password's title/password pair
// without the folder column LastPass and Bitwarden add. Both the legacy
// (title,url,username,password,notes,otp) and 1Password 8
// (Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes) sets qualify.
func (p *CSVImporter) MatchHeaders(headers []string) bool {
	present := csvutil.HeaderSet(headers)

	if !present["title"] || !present["password"] {
		return false
	}
	for _, col := range foreignColumns {
		if present[col] {
			return false
		}
	}
	return true
}

// Parse streams the CSV, skipping unusable rows with a warning rather than
// aborting the import.
func (p *CSVImporter) Parse(r io.ReaderAt, size int64, opts importers.ImportOptions) (*importers.ImportResult, error) {
	result := &importers.ImportResult{}

	err := csvutil.ForEachRow(r, size, func(row *csvutil.Row) error {
		secrets, warnings := p.normalizeRow(row)
		result.Warnings = append(result.Warnings, warnings...)
		result.Secrets = append(result.Secrets, secrets...)
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

// normalizeRow yields the row's primary secret plus a companion 2FA secret when
// a seed column holds a usable value. Archived and empty rows yield nothing; a
// row with content that maps to no secret is reported.
func (p *CSVImporter) normalizeRow(row *csvutil.Row) ([]importers.ImportedSecret, []string) {
	// A delimiter-only line is exporter noise, not lost data.
	if row.IsEmpty() || csvutil.Truthy(row.Get("archived")) {
		return nil, nil
	}

	var warnings []string

	title := row.Get("title")
	if title == "" {
		title = "Untitled Secret"
	}

	notes := row.Get("notes")
	targetURL := ""
	if u := row.Get("url"); validation.IsValidEndpoint(u) {
		targetURL = u
	}

	labels := csvutil.SplitLabels(row.Get("tags"))
	if csvutil.Truthy(row.Get("favorite")) {
		labels = append(labels, "favorite")
	}

	rawTOTP := row.First(totpColumns...)

	var (
		secrets    []importers.ImportedSecret
		payload    []byte
		secretType importers.SecretType
		err        error
	)

	switch {
	case row.Has("username") || row.Has("password"):
		secretType = importers.TypeLoginPassword
		payload, err = json.Marshal(map[string]string{
			"login":    row.Get("username"),
			"password": row.Get("password"),
		})

	case notes != "":
		secretType = importers.TypeSecurityNotes
		payload, err = json.Marshal(map[string]string{"securityNotes": notes})
	}

	switch {
	case err != nil:
		warnings = append(warnings, fmt.Sprintf("line %d: failed to encode payload for %q: %v", row.Line, title, err))
	case payload != nil:
		secrets = append(secrets, importers.ImportedSecret{
			Name:    title,
			Type:    secretType,
			URL:     targetURL,
			Labels:  labels,
			Notes:   notes,
			Payload: payload,
		})
	case rawTOTP == "":
		// Content but no credentials, notes or seed: nothing to import.
		warnings = append(warnings, fmt.Sprintf("line %d: %q has no credentials, notes or 2FA seed, skipped", row.Line, title))
	}

	totp, err := importers.BuildCompanionTOTP(title, rawTOTP, targetURL, notes, labels, len(secrets) > 0)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("line %d: %v", row.Line, err))
	} else if totp != nil {
		secrets = append(secrets, *totp)
	}

	return secrets, warnings
}
