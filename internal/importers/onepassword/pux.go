// Package onepassword parses 1Password exports: 1PUX archives (and their raw
// export.data JSON) plus the CSV layout the desktop app writes.
package onepassword

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/validation"
)

// PUXImporter parses 1Password 1PUX zip archives and raw export.data JSON files.
type PUXImporter struct{}

func NewPUXImporter() *PUXImporter {
	return &PUXImporter{}
}

// 1PUX Data structures for unmarshaling
type onePuxData struct {
	Accounts []onePuxAccount `json:"accounts"`
}

type onePuxAccount struct {
	Attrs  onePuxAccountAttrs `json:"attrs"`
	Vaults []onePuxVault      `json:"vaults"`
}

type onePuxAccountAttrs struct {
	AccountName string `json:"accountName"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	UUID        string `json:"uuid"`
	Domain      string `json:"domain"`
}

type onePuxVault struct {
	Attrs onePuxVaultAttrs `json:"attrs"`
	Items []onePuxItem     `json:"items"`
}

type onePuxVaultAttrs struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Type string `json:"type"`
	Desc string `json:"desc"`
}

type onePuxItem struct {
	UUID         string         `json:"uuid"`
	CategoryUUID string         `json:"categoryUuid"`
	State        string         `json:"state"`
	FavIndex     int            `json:"favIndex"`
	Overview     onePuxOverview `json:"overview"`
	Details      onePuxDetails  `json:"details"`
}

type onePuxOverview struct {
	Title    string      `json:"title"`
	Subtitle string      `json:"subtitle"`
	URL      string      `json:"url"`
	URLs     []onePuxURL `json:"urls"`
	Tags     []string    `json:"tags"`
}

type onePuxURL struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type onePuxDetails struct {
	NotesPlain  string             `json:"notesPlain"`
	LoginFields []onePuxLoginField `json:"loginFields"`
	Sections    []onePuxSection    `json:"sections"`
}

type onePuxLoginField struct {
	Value       string `json:"value"`
	Name        string `json:"name"`
	FieldType   string `json:"fieldType"`
	Designation string `json:"designation"`
}

type onePuxSection struct {
	Title  string        `json:"title"`
	Name   string        `json:"name"`
	Fields []onePuxField `json:"fields"`
}

type onePuxField struct {
	Title string                 `json:"title"`
	ID    string                 `json:"id"`
	Value map[string]interface{} `json:"value"`
}

// ProviderName identifies the resolved source format for CLI output.
func (p *PUXImporter) ProviderName() string {
	return "1Password 1PUX"
}

func (p *PUXImporter) Parse(r io.ReaderAt, size int64, opts importers.ImportOptions) (*importers.ImportResult, error) {
	jsonData, err := p.extractJSON(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to extract 1PUX data: %w", err)
	}

	var export onePuxData
	if err := json.Unmarshal(jsonData, &export); err != nil {
		return nil, fmt.Errorf("failed to parse 1PUX JSON: %w", err)
	}

	var results []importers.ImportedSecret
	var warnings []string

	for _, account := range export.Accounts {
		for _, vault := range account.Vaults {
			// Vault names match hierarchically; a UUID is an exact identifier.
			if !importers.MatchesScope(vault.Attrs.Name, opts.VaultFilter) &&
				!strings.EqualFold(vault.Attrs.UUID, opts.VaultFilter) {
				continue
			}

			for _, item := range vault.Items {
				if item.State == "archived" {
					continue
				}

				secrets, itemWarnings := p.normalizeItem(item, vault.Attrs.Name)
				results = append(results, secrets...)
				warnings = append(warnings, itemWarnings...)
			}
		}
	}

	// Warnings explain which items were dropped, so they travel with the error.
	result := &importers.ImportResult{Secrets: results, Warnings: warnings}
	if len(results) == 0 {
		return result, importers.ErrEmptyExport
	}
	return result, nil
}

func (p *PUXImporter) extractJSON(r io.ReaderAt, size int64) ([]byte, error) {
	// Check if this is a ZIP archive by inspecting magic header bytes
	header := make([]byte, 4)
	if _, err := r.ReadAt(header, 0); err == nil && bytes.Equal(header, []byte("PK\x03\x04")) {
		zipReader, err := zip.NewReader(r, size)
		if err != nil {
			return nil, fmt.Errorf("failed to open zip reader: %w", err)
		}

		for _, file := range zipReader.File {
			if file.Name == "export.data" {
				rc, err := file.Open()
				if err != nil {
					return nil, fmt.Errorf("failed to open export.data inside zip: %w", err)
				}
				defer func() { _ = rc.Close() }()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("export.data not found in 1PUX zip archive")
	}

	// Otherwise, treat as raw JSON stream
	return io.ReadAll(io.NewSectionReader(r, 0, size))
}

// normalizeItem maps one 1PUX item to its Ennote secrets. vaultName becomes the
// first label, as folder and grouping do in the CSV providers. An item that maps
// to nothing yields a warning, not an error.
func (p *PUXImporter) normalizeItem(item onePuxItem, vaultName string) ([]importers.ImportedSecret, []string) {
	var secrets []importers.ImportedSecret
	var warnings []string

	title := strings.TrimSpace(item.Overview.Title)
	if title == "" {
		title = strings.TrimSpace(item.Overview.Subtitle)
	}
	if title == "" {
		title = "Untitled Secret"
	}

	targetURL := ""
	if validation.IsValidEndpoint(item.Overview.URL) {
		targetURL = item.Overview.URL
	} else if len(item.Overview.URLs) > 0 && validation.IsValidEndpoint(item.Overview.URLs[0].URL) {
		targetURL = item.Overview.URLs[0].URL
	}

	// Account-level attrs (accountName, email, uuid, domain) describe the
	// exporting identity, not a secret, and are ignored.
	labels := make([]string, 0, len(item.Overview.Tags)+2)
	if vault := strings.TrimSpace(vaultName); vault != "" {
		labels = append(labels, vault)
	}
	for _, tag := range item.Overview.Tags {
		if t := strings.TrimSpace(tag); t != "" {
			labels = append(labels, t)
		}
	}
	if item.FavIndex > 0 {
		labels = append(labels, "favorite")
	}

	notes := strings.TrimSpace(item.Details.NotesPlain)

	var primarySecret *importers.ImportedSecret

	switch item.CategoryUUID {
	case "001", "005": // Login or Password
		username, password := p.extractLoginPassword(item)
		if username != "" || password != "" {
			payloadBytes, err := json.Marshal(map[string]string{
				"login":    username,
				"password": password,
			})
			if err == nil {
				primarySecret = &importers.ImportedSecret{
					Name:    title,
					Type:    importers.TypeLoginPassword,
					URL:     targetURL,
					Labels:  labels,
					Notes:   notes,
					Payload: payloadBytes,
				}
			}
		}

	case "003": // Secure Note
		// An empty note body is not a secret: fall through to the section and
		// notes fallbacks below, as the CSV providers do.
		if notes != "" {
			payloadBytes, err := json.Marshal(map[string]string{
				"securityNotes": notes,
			})
			if err == nil {
				primarySecret = &importers.ImportedSecret{
					Name:    title,
					Type:    importers.TypeSecurityNotes,
					URL:     targetURL,
					Labels:  labels,
					Notes:   notes,
					Payload: payloadBytes,
				}
			}
		}
	}

	if primarySecret == nil {
		// Identity (004), Database (102), Server (109), Software License (100),
		// and logins or notes whose content lives in sections.
		kvMap := p.flattenSections(item.Details.Sections)
		if len(kvMap) > 0 {
			payloadBytes, kvWarnings, err := importers.BuildKeysValues(title, kvMap)
			warnings = append(warnings, kvWarnings...)
			if err == nil {
				primarySecret = &importers.ImportedSecret{
					Name:    title,
					Type:    importers.TypeKeysValues,
					URL:     targetURL,
					Labels:  labels,
					Notes:   notes,
					Payload: payloadBytes,
				}
			}
		}
	}

	if primarySecret == nil && notes != "" {
		// Fallback to Security Notes if there is any notes content
		payloadBytes, err := json.Marshal(map[string]string{
			"securityNotes": notes,
		})
		if err == nil {
			primarySecret = &importers.ImportedSecret{
				Name:    title,
				Type:    importers.TypeSecurityNotes,
				URL:     targetURL,
				Labels:  labels,
				Notes:   notes,
				Payload: payloadBytes,
			}
		}
	}

	if primarySecret != nil {
		secrets = append(secrets, *primarySecret)
	}

	// Shared with the CSV providers, so a malformed seed is reported. Every
	// diagnostic names its vault: a title alone is ambiguous across vaults.
	totp, err := importers.BuildCompanionTOTP(title, p.rawTOTP(item), targetURL, notes, labels, primarySecret != nil)
	if err != nil {
		warnings = append(warnings, vaultPrefix(vaultName)+err.Error())
	} else if totp != nil {
		secrets = append(secrets, *totp)
	}

	if len(secrets) == 0 {
		warnings = append(warnings, fmt.Sprintf("%sitem %q (category %s) maps to no secret type, skipped", vaultPrefix(vaultName), title, item.CategoryUUID))
	}

	return secrets, warnings
}

// vaultPrefix qualifies a diagnostic with its vault. Messages that already name
// the item need only this prefix.
func vaultPrefix(vaultName string) string {
	if vault := strings.TrimSpace(vaultName); vault != "" {
		return fmt.Sprintf("vault %q: ", vault)
	}
	return ""
}

func (p *PUXImporter) extractLoginPassword(item onePuxItem) (username string, password string) {
	for _, field := range item.Details.LoginFields {
		val := strings.TrimSpace(field.Value)
		if val == "" {
			continue
		}

		if field.Designation == "username" {
			username = val
		} else if field.Designation == "password" {
			password = val
		} else if username == "" && (field.Name == "username" || field.Name == "email" || field.Name == "login" || field.FieldType == "E") {
			username = val
		} else if password == "" && (field.Name == "password" || field.Name == "master-password" || field.FieldType == "P") {
			password = val
		}
	}

	// If not found in loginFields, search sections
	if username == "" || password == "" {
		for _, section := range item.Details.Sections {
			for _, field := range section.Fields {
				val := p.extractFieldValueString(field.Value)
				if val == "" {
					continue
				}

				lowerTitle := strings.ToLower(field.Title)
				lowerID := strings.ToLower(field.ID)

				if username == "" && (lowerTitle == "username" || lowerTitle == "email" || lowerID == "username" || lowerID == "email") {
					username = val
				} else if password == "" && (lowerTitle == "password" || lowerID == "password") {
					password = val
				}
			}
		}
	}

	return username, password
}

// rawTOTP returns the raw seed of the first TOTP-bearing field, leaving
// validation to importers.ExtractTOTP. A candidate that parses wins; if none
// parse, the first is returned so the failure is reported.
func (p *PUXImporter) rawTOTP(item onePuxItem) string {
	first := ""
	consider := func(val string) bool {
		if first == "" {
			first = val
		}
		if seed, err := importers.ExtractTOTP(val); err == nil && seed != "" {
			first = val
			return true
		}
		return false
	}

	for _, field := range item.Details.LoginFields {
		val := strings.TrimSpace(field.Value)
		if val == "" {
			continue
		}
		if field.Designation == "totp" || strings.Contains(strings.ToLower(field.Name), "totp") || strings.HasPrefix(val, "otpauth://") {
			if consider(val) {
				return first
			}
		}
	}

	for _, section := range item.Details.Sections {
		for _, field := range section.Fields {
			val := p.extractFieldValueString(field.Value)
			if val == "" {
				continue
			}

			lowerTitle := strings.ToLower(field.Title)
			lowerID := strings.ToLower(field.ID)

			if strings.Contains(lowerTitle, "one-time password") || strings.Contains(lowerTitle, "totp") || strings.Contains(lowerTitle, "2fa") ||
				strings.Contains(lowerID, "totp") || strings.HasPrefix(val, "otpauth://") {
				if consider(val) {
					return first
				}
			}
		}
	}

	return first
}

func (p *PUXImporter) flattenSections(sections []onePuxSection) map[string]string {
	result := make(map[string]string)

	for _, section := range sections {
		for _, field := range section.Fields {
			val := p.extractFieldValueString(field.Value)
			if val == "" {
				continue
			}

			key := strings.TrimSpace(field.Title)
			if key == "" {
				key = strings.TrimSpace(field.ID)
			}
			if key == "" {
				continue
			}

			// Don't overwrite if already set, or qualify with section title
			if _, exists := result[key]; exists && section.Title != "" {
				key = fmt.Sprintf("%s - %s", section.Title, key)
			}

			result[key] = val
		}
	}

	return result
}

func (p *PUXImporter) extractFieldValueString(valMap map[string]interface{}) string {
	if valMap == nil {
		return ""
	}

	for k, v := range valMap {
		if v == nil {
			continue
		}

		switch k {
		case "string", "concealed", "phone", "url":
			if strVal, ok := v.(string); ok {
				return strings.TrimSpace(strVal)
			}

		case "date":
			if num, ok := v.(float64); ok && num > 0 {
				t := time.Unix(int64(num), 0).UTC()
				return t.Format("2006-01-02")
			}

		case "email":
			if emailMap, ok := v.(map[string]interface{}); ok {
				if emailAddr, ok := emailMap["email_address"].(string); ok {
					return strings.TrimSpace(emailAddr)
				}
			}

		case "address":
			if addrMap, ok := v.(map[string]interface{}); ok {
				parts := make([]string, 0)
				for _, fieldName := range []string{"street", "city", "state", "zip", "country"} {
					if part, ok := addrMap[fieldName].(string); ok && strings.TrimSpace(part) != "" {
						parts = append(parts, strings.TrimSpace(part))
					}
				}
				if len(parts) > 0 {
					return strings.Join(parts, ", ")
				}
			}

		default:
			if flat := strings.TrimSpace(importers.FlattenValue(v)); flat != "" {
				return flat
			}
		}
	}

	return ""
}
