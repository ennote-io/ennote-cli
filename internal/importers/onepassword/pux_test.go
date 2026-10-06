package onepassword

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

func decodeKeysValues(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	var decoded map[string]map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not a flat string map: %v (payload=%s)", err, payload)
	}
	return decoded["keysValues"]
}

func createSynthetic1PUXJSON() []byte {
	data := map[string]interface{}{
		"accounts": []map[string]interface{}{
			{
				"attrs": map[string]interface{}{
					"accountName": "Test Account",
					"email":       "user@example.com",
					"uuid":        "ACC123456789",
				},
				"vaults": []map[string]interface{}{
					{
						"attrs": map[string]interface{}{
							"uuid": "VAULT-PERSONAL",
							"name": "Personal",
							"type": "P",
						},
						"items": []map[string]interface{}{
							// 1. Standard Login with TOTP
							{
								"uuid":         "item-login-1",
								"categoryUuid": "001",
								"state":        "active",
								"favIndex":     1,
								"overview": map[string]interface{}{
									"title": "Example Login",
									"url":   "https://login.example.com",
									"tags":  []string{"prod", "web"},
								},
								"details": map[string]interface{}{
									"notesPlain": "Some login note",
									"loginFields": []map[string]interface{}{
										{
											"designation": "username",
											"value":       "testuser@example.com",
										},
										{
											"designation": "password",
											"value":       "SecretPass123!",
										},
										{
											"designation": "totp",
											"value":       "otpauth://totp/Example:testuser?secret=JBSWY3DPEHPK3PXP&issuer=Example",
										},
									},
								},
							},
							// 2. Secure Note
							{
								"uuid":         "item-note-1",
								"categoryUuid": "003",
								"state":        "active",
								"overview": map[string]interface{}{
									"title": "Production Instructions",
									"tags":  []string{"docs"},
								},
								"details": map[string]interface{}{
									"notesPlain": "# Deployment Runbook\n1. Step one\n2. Step two",
								},
							},
							// 3. Identity (Multi-field sections)
							{
								"uuid":         "item-identity-1",
								"categoryUuid": "004",
								"state":        "active",
								"overview": map[string]interface{}{
									"title": "Test Identity",
								},
								"details": map[string]interface{}{
									"notesPlain": "Personal identity record",
									"sections": []map[string]interface{}{
										{
											"title": "Name",
											"fields": []map[string]interface{}{
												{
													"title": "first name",
													"value": map[string]interface{}{"string": "John"},
												},
												{
													"title": "last name",
													"value": map[string]interface{}{"string": "Doe"},
												},
											},
										},
										{
											"title": "Address",
											"fields": []map[string]interface{}{
												{
													"title": "home address",
													"value": map[string]interface{}{
														"address": map[string]interface{}{
															"street":  "123 Main St",
															"city":    "Springfield",
															"state":   "IL",
															"zip":     "62701",
															"country": "USA",
														},
													},
												},
												{
													"title": "EXPIRY",
													"value": map[string]interface{}{"monthYear": 202401},
												},
												{
													"title": "SSH_KEY",
													"value": map[string]interface{}{"sshKey": map[string]interface{}{"privateKey": "abc"}},
												},
											},
										},
									},
								},
							},
							// 4. Database Credentials (Category 102 -> KEYS_VALUES)
							{
								"uuid":         "item-db-1",
								"categoryUuid": "102",
								"state":        "active",
								"overview": map[string]interface{}{
									"title": "PostgreSQL Prod",
									"url":   "10.0.0.5:5432",
									"tags":  []string{"db", "infra"},
								},
								"details": map[string]interface{}{
									"sections": []map[string]interface{}{
										{
											"title": "Database",
											"fields": []map[string]interface{}{
												{
													"title": "hostname",
													"value": map[string]interface{}{"string": "db.prod.internal"},
												},
												{
													"title": "port",
													"value": map[string]interface{}{"string": "5432"},
												},
												{
													"title": "username",
													"value": map[string]interface{}{"string": "pgadmin"},
												},
												{
													"title": "password",
													"value": map[string]interface{}{"concealed": "SuperDbPass999!"},
												},
											},
										},
									},
								},
							},
							// 5. Archived item (should be skipped)
							{
								"uuid":         "item-archived-1",
								"categoryUuid": "001",
								"state":        "archived",
								"overview": map[string]interface{}{
									"title": "Old Archived Service",
								},
							},
						},
					},
					{
						"attrs": map[string]interface{}{
							"uuid": "VAULT-WORK",
							"name": "Work",
							"type": "U",
						},
						"items": []map[string]interface{}{
							{
								"uuid":         "item-work-1",
								"categoryUuid": "001",
								"state":        "active",
								"overview": map[string]interface{}{
									"title": "Work Portal",
								},
								"details": map[string]interface{}{
									"loginFields": []map[string]interface{}{
										{"designation": "username", "value": "workuser"},
										{"designation": "password", "value": "WorkPass123"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	b, _ := json.Marshal(data)
	return b
}

func createSynthetic1PUXZip(t *testing.T) []byte {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	attrWriter, err := zw.Create("export.attributes")
	if err != nil {
		t.Fatalf("failed to create attributes in zip: %v", err)
	}
	_, _ = attrWriter.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export"}`))

	dataWriter, err := zw.Create("export.data")
	if err != nil {
		t.Fatalf("failed to create export.data in zip: %v", err)
	}
	_, _ = dataWriter.Write(createSynthetic1PUXJSON())

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}

func TestOnePUXImporter_RawJSON(t *testing.T) {
	jsonData := createSynthetic1PUXJSON()
	r := bytes.NewReader(jsonData)
	importer := NewPUXImporter()

	res, err := importer.Parse(r, int64(len(jsonData)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error parsing 1PUX raw JSON: %v", err)
	}
	secrets := res.Secrets

	// Expected:
	// From Personal vault:
	// 1. Example Login (LOGIN_PASSWORD)
	// 2. Example Login 2FA (TWO_FACTOR) companion secret
	// 3. Production Instructions (SECURITY_NOTES)
	// 4. Test Identity (KEYS_VALUES)
	// 5. PostgreSQL Prod (KEYS_VALUES)
	// From Work vault:
	// 6. Work Portal (LOGIN_PASSWORD)
	// Total: 6 secrets (archived item skipped)
	if len(secrets) != 6 {
		t.Fatalf("expected 6 imported secrets, got %d", len(secrets))
	}

	// Verify Login secret
	loginSecret := secrets[0]
	if loginSecret.Name != "Example Login" || loginSecret.Type != importers.TypeLoginPassword {
		t.Errorf("unexpected login secret: %+v", loginSecret)
	}
	if loginSecret.URL != "https://login.example.com" {
		t.Errorf("expected URL 'https://login.example.com', got %q", loginSecret.URL)
	}
	var loginPayload map[string]string
	if err := json.Unmarshal(loginSecret.Payload, &loginPayload); err != nil {
		t.Fatalf("failed to unmarshal login payload: %v", err)
	}
	if loginPayload["login"] != "testuser@example.com" || loginPayload["password"] != "SecretPass123!" {
		t.Errorf("unexpected login payload: %+v", loginPayload)
	}

	// Verify Companion 2FA secret
	totpSecret := secrets[1]
	if totpSecret.Name != "Example Login 2FA" || totpSecret.Type != importers.TypeTwoFactor {
		t.Errorf("unexpected TOTP secret: %+v", totpSecret)
	}
	var totpPayload map[string]string
	if err := json.Unmarshal(totpSecret.Payload, &totpPayload); err != nil {
		t.Fatalf("failed to unmarshal totp payload: %v", err)
	}
	if totpPayload["securityCode"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected securityCode 'JBSWY3DPEHPK3PXP', got %q", totpPayload["securityCode"])
	}

	// Verify Secure Note
	noteSecret := secrets[2]
	if noteSecret.Name != "Production Instructions" || noteSecret.Type != importers.TypeSecurityNotes {
		t.Errorf("unexpected note secret: %+v", noteSecret)
	}
	var notePayload map[string]string
	if err := json.Unmarshal(noteSecret.Payload, &notePayload); err != nil {
		t.Fatalf("failed to unmarshal note payload: %v", err)
	}
	if !bytes.Contains([]byte(notePayload["securityNotes"]), []byte("Deployment Runbook")) {
		t.Errorf("unexpected securityNotes content: %q", notePayload["securityNotes"])
	}

	// Verify Identity (KEYS_VALUES): flat string map, keys preserved verbatim
	identitySecret := secrets[3]
	if identitySecret.Name != "Test Identity" || identitySecret.Type != importers.TypeKeysValues {
		t.Errorf("unexpected identity secret: %+v", identitySecret)
	}
	kv := decodeKeysValues(t, identitySecret.Payload)
	if kv["first name"] != "John" || kv["last name"] != "Doe" {
		t.Errorf("unexpected identity keysValues: %+v", kv)
	}
	if kv["home address"] != "123 Main St, Springfield, IL, 62701, USA" {
		t.Errorf("unexpected formatted address: %q", kv["home address"])
	}
	if kv["EXPIRY"] != "202401" {
		t.Errorf("expected numeric field coerced to string, got %q", kv["EXPIRY"])
	}
	if kv["SSH_KEY"] != `{"privateKey":"abc"}` {
		t.Errorf("expected structured field compact-JSON stringified, got %q", kv["SSH_KEY"])
	}

	// Keys 1Password generates with spaces import cleanly; a warning here would
	// fire on every Identity item without telling the user anything actionable.
	if len(res.Warnings) != 0 {
		t.Errorf("expected no warnings for a clean 1PUX import, got %v", res.Warnings)
	}
}

func TestOnePUXImporter_ZipArchive(t *testing.T) {
	zipData := createSynthetic1PUXZip(t)
	r := bytes.NewReader(zipData)
	importer := NewPUXImporter()

	res, err := importer.Parse(r, int64(len(zipData)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error parsing 1PUX zip: %v", err)
	}
	secrets := res.Secrets

	if len(secrets) != 6 {
		t.Fatalf("expected 6 secrets from zip, got %d", len(secrets))
	}
}

func TestOnePUXImporter_LabelsCarryVaultAndFavorite(t *testing.T) {
	jsonData := createSynthetic1PUXJSON()
	r := bytes.NewReader(jsonData)

	res, err := NewPUXImporter().Parse(r, int64(len(jsonData)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byName := make(map[string][]string, len(res.Secrets))
	for _, s := range res.Secrets {
		byName[s.Name] = s.Labels
	}

	// Vault name first, then item tags, then favorite - the ordering the CSV
	// providers use for folder/grouping, tags and favorites.
	if got := byName["Example Login"]; !slices.Equal(got, []string{"Personal", "prod", "web", "favorite"}) {
		t.Errorf("login labels = %v, want vault, tags and favorite", got)
	}
	// The 2FA companion inherits its parent's labels.
	if got := byName["Example Login 2FA"]; !slices.Equal(got, []string{"Personal", "prod", "web", "favorite"}) {
		t.Errorf("companion labels = %v, want the parent's labels", got)
	}
	// Non-favorite item in another vault: vault name only.
	if got := byName["Work Portal"]; !slices.Equal(got, []string{"Work"}) {
		t.Errorf("work labels = %v, want [Work]", got)
	}
	if got := byName["Production Instructions"]; !slices.Equal(got, []string{"Personal", "docs"}) {
		t.Errorf("note labels = %v, want vault plus tag", got)
	}

	// Invariant: every secret produced from a vault carries that vault's name as
	// its first label, whatever category the item mapped to.
	for _, vault := range []string{"Personal", "Work"} {
		filtered, err := NewPUXImporter().Parse(bytes.NewReader(jsonData), int64(len(jsonData)), importers.ImportOptions{
			VaultFilter: vault,
		})
		if err != nil {
			t.Fatalf("parsing vault %q failed: %v", vault, err)
		}
		if len(filtered.Secrets) == 0 {
			t.Fatalf("vault %q produced no secrets", vault)
		}
		for _, s := range filtered.Secrets {
			if len(s.Labels) == 0 || s.Labels[0] != vault {
				t.Errorf("secret %q from vault %q has labels %v, want %q first", s.Name, vault, s.Labels, vault)
			}
		}
	}
}

func TestOnePUXImporter_VaultFilter(t *testing.T) {
	jsonData := createSynthetic1PUXJSON()
	r := bytes.NewReader(jsonData)
	importer := NewPUXImporter()

	// Filter only "Work" vault
	res, err := importer.Parse(r, int64(len(jsonData)), importers.ImportOptions{
		VaultFilter: "Work",
	})
	if err != nil {
		t.Fatalf("unexpected error parsing with vault filter: %v", err)
	}
	secrets := res.Secrets

	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret for Work vault filter, got %d", len(secrets))
	}
	if secrets[0].Name != "Work Portal" {
		t.Errorf("expected 'Work Portal', got %q", secrets[0].Name)
	}
}

func TestOnePUXImporter_EmptyAndErrors(t *testing.T) {
	emptyData := []byte(`{"accounts":[{"attrs":{"name":"Empty"},"vaults":[{"attrs":{"name":"Empty"},"items":[]}]}]}`)
	r := bytes.NewReader(emptyData)
	importer := NewPUXImporter()

	_, err := importer.Parse(r, int64(len(emptyData)), importers.ImportOptions{})
	if err != importers.ErrEmptyExport {
		t.Fatalf("expected importers.ErrEmptyExport, got %v", err)
	}

	// Non-matching vault
	jsonData := createSynthetic1PUXJSON()
	rJSON := bytes.NewReader(jsonData)
	_, err = importer.Parse(rJSON, int64(len(jsonData)), importers.ImportOptions{
		VaultFilter: "NonExistentVault",
	})
	if err != importers.ErrEmptyExport {
		t.Fatalf("expected importers.ErrEmptyExport for non-matching vault filter, got %v", err)
	}

	// Corrupt JSON
	corruptData := []byte(`{not valid json}`)
	rCorrupt := bytes.NewReader(corruptData)
	_, err = importer.Parse(rCorrupt, int64(len(corruptData)), importers.ImportOptions{})
	if err == nil {
		t.Fatal("expected error parsing corrupt JSON, got nil")
	}
}

// An empty Secure Note body is not a secret, and an item that maps to nothing
// must say so: both outcomes were previously silent (an empty SECURITY_NOTES
// payload, and warnings discarded with the per-item error).
func TestOnePUXImporter_UnmappableItemsWarnAndDoNotImport(t *testing.T) {
	data := []byte(`{"accounts":[{"attrs":{"name":"Acct"},"vaults":[{"attrs":{"name":"Personal"},"items":[
		{"uuid":"a","categoryUuid":"003","state":"active","overview":{"title":"Blank Note"},"details":{"notesPlain":"   ","sections":[]}},
		{"uuid":"b","categoryUuid":"004","state":"active","overview":{"title":"Blank Identity"},"details":{"notesPlain":"","sections":[]}},
		{"uuid":"c","categoryUuid":"001","state":"active","overview":{"title":"Login"},"details":{"loginFields":[{"designation":"username","value":"u"},{"designation":"password","value":"p"}]}}
	]}]}]}`)

	res, err := NewPUXImporter().Parse(bytes.NewReader(data), int64(len(data)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Login" {
		t.Fatalf("Parse() secrets = %+v, want only the Login item", res.Secrets)
	}
	if len(res.Warnings) != 2 {
		t.Fatalf("Parse() warnings = %v, want one per unmappable item", res.Warnings)
	}
	for _, want := range []string{"Blank Note", "Blank Identity"} {
		if !strings.Contains(strings.Join(res.Warnings, "\n"), want) {
			t.Errorf("warnings %v do not mention %q", res.Warnings, want)
		}
	}
}

// Warnings are the entire answer when nothing maps, so they must survive the
// ErrEmptyExport return.
func TestOnePUXImporter_EmptyExportKeepsWarnings(t *testing.T) {
	data := []byte(`{"accounts":[{"attrs":{"name":"Acct"},"vaults":[{"attrs":{"name":"Personal"},"items":[
		{"uuid":"a","categoryUuid":"004","state":"active","overview":{"title":"Blank Identity"},"details":{"notesPlain":"","sections":[]}}
	]}]}]}`)

	res, err := NewPUXImporter().Parse(bytes.NewReader(data), int64(len(data)), importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("Parse() error = %v, want ErrEmptyExport", err)
	}
	if res == nil || len(res.Warnings) != 1 {
		t.Fatalf("Parse() result = %+v, want the dropped-item warning alongside the error", res)
	}
}

// --vault must mean the same thing for a 1PUX vault as for a CSV folder
// column: hierarchical, separator-insensitive, and not a prefix match.
func TestOnePUXImporter_VaultFilterIsHierarchical(t *testing.T) {
	data := []byte(`{"accounts":[{"attrs":{"name":"Acct"},"vaults":[
		{"attrs":{"name":"Dev/Cloud"},"items":[{"uuid":"a","categoryUuid":"001","state":"active","overview":{"title":"Nested"},"details":{"loginFields":[{"designation":"username","value":"u"}]}}]},
		{"attrs":{"name":"Development"},"items":[{"uuid":"b","categoryUuid":"001","state":"active","overview":{"title":"Sibling"},"details":{"loginFields":[{"designation":"username","value":"u"}]}}]}
	]}]}`)

	res, err := NewPUXImporter().Parse(bytes.NewReader(data), int64(len(data)), importers.ImportOptions{VaultFilter: "dev"})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Nested" {
		t.Fatalf("Parse() secrets = %+v, want only the Dev/Cloud item", res.Secrets)
	}
}

// A seed 1Password wrote but Ennote cannot use is lost data: the CSV providers
// warn about it, and the 1PUX path must not swallow it.
func TestOnePUXImporter_MalformedSeedWarns(t *testing.T) {
	data := []byte(`{"accounts":[{"attrs":{"name":"Acct"},"vaults":[{"attrs":{"name":"Personal"},"items":[
		{"uuid":"a","categoryUuid":"001","state":"active","overview":{"title":"GitHub"},"details":{"loginFields":[
			{"designation":"username","value":"octocat"},
			{"designation":"password","value":"pw"},
			{"designation":"totp","value":"NOT_BASE32_818"}
		]}}
	]}]}]}`)

	res, err := NewPUXImporter().Parse(bytes.NewReader(data), int64(len(data)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("Parse() secrets = %+v, want the login only", res.Secrets)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], `invalid 2FA seed for "GitHub"`) {
		t.Fatalf("Parse() warnings = %v, want the malformed-seed report", res.Warnings)
	}
}
