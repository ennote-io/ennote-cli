package importers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"
)

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
	importer := New1PUXImporter()

	secrets, err := importer.Parse(r, int64(len(jsonData)), ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error parsing 1PUX raw JSON: %v", err)
	}

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
	if loginSecret.Name != "Example Login" || loginSecret.Type != TypeLoginPassword {
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
	if totpSecret.Name != "Example Login 2FA" || totpSecret.Type != TypeTwoFactor {
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
	if noteSecret.Name != "Production Instructions" || noteSecret.Type != TypeSecurityNotes {
		t.Errorf("unexpected note secret: %+v", noteSecret)
	}
	var notePayload map[string]string
	if err := json.Unmarshal(noteSecret.Payload, &notePayload); err != nil {
		t.Fatalf("failed to unmarshal note payload: %v", err)
	}
	if !bytes.Contains([]byte(notePayload["securityNotes"]), []byte("Deployment Runbook")) {
		t.Errorf("unexpected securityNotes content: %q", notePayload["securityNotes"])
	}

	// Verify Identity (KEYS_VALUES)
	identitySecret := secrets[3]
	if identitySecret.Name != "Test Identity" || identitySecret.Type != TypeKeysValues {
		t.Errorf("unexpected identity secret: %+v", identitySecret)
	}
	var identityPayload map[string]map[string]interface{}
	if err := json.Unmarshal(identitySecret.Payload, &identityPayload); err != nil {
		t.Fatalf("failed to unmarshal identity payload: %v", err)
	}
	kv := identityPayload["keysValues"]
	if kv["first name"] != "John" || kv["last name"] != "Doe" {
		t.Errorf("unexpected identity keysValues: %+v", kv)
	}
	if kv["home address"] != "123 Main St, Springfield, IL, 62701, USA" {
		t.Errorf("unexpected formatted address: %q", kv["home address"])
	}
}

func TestOnePUXImporter_ZipArchive(t *testing.T) {
	zipData := createSynthetic1PUXZip(t)
	r := bytes.NewReader(zipData)
	importer := New1PUXImporter()

	secrets, err := importer.Parse(r, int64(len(zipData)), ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error parsing 1PUX zip: %v", err)
	}

	if len(secrets) != 6 {
		t.Fatalf("expected 6 secrets from zip, got %d", len(secrets))
	}
}

func TestOnePUXImporter_VaultFilter(t *testing.T) {
	jsonData := createSynthetic1PUXJSON()
	r := bytes.NewReader(jsonData)
	importer := New1PUXImporter()

	// Filter only "Work" vault
	secrets, err := importer.Parse(r, int64(len(jsonData)), ImportOptions{
		VaultFilter: "Work",
	})
	if err != nil {
		t.Fatalf("unexpected error parsing with vault filter: %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret for Work vault filter, got %d", len(secrets))
	}
	if secrets[0].Name != "Work Portal" {
		t.Errorf("expected 'Work Portal', got %q", secrets[0].Name)
	}
}

func TestDetectFormat(t *testing.T) {
	zipData := createSynthetic1PUXZip(t)
	rZip := bytes.NewReader(zipData)

	fmtDetected, err := DetectFormat(rZip, int64(len(zipData)), "export.1pux")
	if err != nil {
		t.Fatalf("failed to detect format: %v", err)
	}
	if fmtDetected != Format1PUX {
		t.Errorf("expected format %q, got %q", Format1PUX, fmtDetected)
	}

	jsonData := createSynthetic1PUXJSON()
	rJSON := bytes.NewReader(jsonData)
	fmtJSON, err := DetectFormat(rJSON, int64(len(jsonData)), "export.data")
	if err != nil {
		t.Fatalf("failed to detect format for json: %v", err)
	}
	if fmtJSON != Format1PUX {
		t.Errorf("expected format %q, got %q", Format1PUX, fmtJSON)
	}
}

func TestOnePUXImporter_EmptyAndErrors(t *testing.T) {
	emptyData := []byte(`{"accounts":[{"attrs":{"name":"Empty"},"vaults":[{"attrs":{"name":"Empty"},"items":[]}]}]}`)
	r := bytes.NewReader(emptyData)
	importer := New1PUXImporter()

	_, err := importer.Parse(r, int64(len(emptyData)), ImportOptions{})
	if err != ErrEmptyExport {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}

	// Non-matching vault
	jsonData := createSynthetic1PUXJSON()
	rJSON := bytes.NewReader(jsonData)
	_, err = importer.Parse(rJSON, int64(len(jsonData)), ImportOptions{
		VaultFilter: "NonExistentVault",
	})
	if err != ErrEmptyExport {
		t.Fatalf("expected ErrEmptyExport for non-matching vault filter, got %v", err)
	}

	// Corrupt JSON
	corruptData := []byte(`{not valid json}`)
	rCorrupt := bytes.NewReader(corruptData)
	_, err = importer.Parse(rCorrupt, int64(len(corruptData)), ImportOptions{})
	if err == nil {
		t.Fatal("expected error parsing corrupt JSON, got nil")
	}
}
