package importers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/validation"
)

// OnePUXImporter parses 1Password 1PUX zip archives and raw export.data JSON files.
type OnePUXImporter struct{}

func New1PUXImporter() *OnePUXImporter {
	return &OnePUXImporter{}
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

func (p *OnePUXImporter) Parse(r io.ReaderAt, size int64, opts ImportOptions) ([]ImportedSecret, error) {
	jsonData, err := p.extractJSON(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to extract 1PUX data: %w", err)
	}

	var export onePuxData
	if err := json.Unmarshal(jsonData, &export); err != nil {
		return nil, fmt.Errorf("failed to parse 1PUX JSON: %w", err)
	}

	var results []ImportedSecret

	for _, account := range export.Accounts {
		for _, vault := range account.Vaults {
			if opts.VaultFilter != "" {
				if !strings.EqualFold(vault.Attrs.Name, opts.VaultFilter) && !strings.EqualFold(vault.Attrs.UUID, opts.VaultFilter) {
					continue
				}
			}

			for _, item := range vault.Items {
				if item.State == "archived" {
					continue
				}

				secrets, err := p.normalizeItem(item)
				if err != nil {
					continue
				}
				results = append(results, secrets...)
			}
		}
	}

	if len(results) == 0 {
		return nil, ErrEmptyExport
	}

	return results, nil
}

func (p *OnePUXImporter) extractJSON(r io.ReaderAt, size int64) ([]byte, error) {
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
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("export.data not found in 1PUX zip archive")
	}

	// Otherwise, treat as raw JSON stream
	return io.ReadAll(io.NewSectionReader(r, 0, size))
}

func (p *OnePUXImporter) normalizeItem(item onePuxItem) ([]ImportedSecret, error) {
	var secrets []ImportedSecret

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

	labels := make([]string, 0, len(item.Overview.Tags))
	for _, tag := range item.Overview.Tags {
		t := strings.TrimSpace(tag)
		if t != "" {
			labels = append(labels, t)
		}
	}

	notes := strings.TrimSpace(item.Details.NotesPlain)

	var primarySecret *ImportedSecret

	switch item.CategoryUUID {
	case "001", "005": // Login or Password
		username, password := p.extractLoginPassword(item)
		if username != "" || password != "" {
			payloadBytes, err := json.Marshal(map[string]string{
				"login":    username,
				"password": password,
			})
			if err == nil {
				primarySecret = &ImportedSecret{
					Name:    title,
					Type:    TypeLoginPassword,
					URL:     targetURL,
					Labels:  labels,
					Notes:   notes,
					Payload: payloadBytes,
				}
			}
		}

	case "003": // Secure Note
		payloadBytes, err := json.Marshal(map[string]string{
			"securityNotes": notes,
		})
		if err == nil {
			primarySecret = &ImportedSecret{
				Name:    title,
				Type:    TypeSecurityNotes,
				URL:     targetURL,
				Labels:  labels,
				Notes:   notes,
				Payload: payloadBytes,
			}
		}
	}

	if primarySecret == nil {
		// For Identity (004), Database (102), Server (109), Software License (100), etc.
		// Or fallback for logins/notes with complex sections:
		kvMap := p.flattenSections(item.Details.Sections)
		if len(kvMap) > 0 {
			payloadBytes, err := json.Marshal(map[string]interface{}{
				"keysValues": kvMap,
			})
			if err == nil {
				primarySecret = &ImportedSecret{
					Name:    title,
					Type:    TypeKeysValues,
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
			primarySecret = &ImportedSecret{
				Name:    title,
				Type:    TypeSecurityNotes,
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

	// Check for embedded TOTP seeds and append as companion 2FA secret
	totpSecret := p.extractTOTP(item)
	if totpSecret != "" {
		totpPayload, err := json.Marshal(map[string]string{
			"securityCode": totpSecret,
		})
		if err == nil {
			secrets = append(secrets, ImportedSecret{
				Name:    fmt.Sprintf("%s 2FA", title),
				Type:    TypeTwoFactor,
				URL:     targetURL,
				Labels:  labels,
				Notes:   notes,
				Payload: totpPayload,
			})
		}
	}

	if len(secrets) > 0 {
		return secrets, nil
	}

	return nil, fmt.Errorf("unable to map item %q to any secret type", title)
}

func (p *OnePUXImporter) extractLoginPassword(item onePuxItem) (username string, password string) {
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

func (p *OnePUXImporter) extractTOTP(item onePuxItem) string {
	// Search in login fields
	for _, field := range item.Details.LoginFields {
		val := strings.TrimSpace(field.Value)
		if val == "" {
			continue
		}
		if field.Designation == "totp" || strings.Contains(strings.ToLower(field.Name), "totp") || strings.HasPrefix(val, "otpauth://") {
			if secret := parseTOTPSecret(val); secret != "" {
				return secret
			}
		}
	}

	// Search in sections
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
				if secret := parseTOTPSecret(val); secret != "" {
					return secret
				}
			}
		}
	}

	return ""
}

func parseTOTPSecret(rawVal string) string {
	rawVal = strings.TrimSpace(rawVal)
	if strings.HasPrefix(rawVal, "otpauth://") {
		u, err := url.Parse(rawVal)
		if err == nil {
			secretParam := u.Query().Get("secret")
			if secretParam != "" {
				rawVal = secretParam
			}
		}
	}

	cleanSecret, err := validation.ParseBase32(rawVal)
	if err != nil {
		return ""
	}
	return cleanSecret
}

func (p *OnePUXImporter) flattenSections(sections []onePuxSection) map[string]string {
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

func (p *OnePUXImporter) extractFieldValueString(valMap map[string]interface{}) string {
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
			if strVal, ok := v.(string); ok && strVal != "" {
				return strings.TrimSpace(strVal)
			}
		}
	}

	return ""
}
