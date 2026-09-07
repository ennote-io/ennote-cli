package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func createSyntheticTestZip(t *testing.T) string {
	data := map[string]interface{}{
		"accounts": []map[string]interface{}{
			{
				"attrs": map[string]interface{}{
					"accountName": "Unit Test Account",
					"email":       "unit@example.com",
					"uuid":        "ACC999",
				},
				"vaults": []map[string]interface{}{
					{
						"attrs": map[string]interface{}{
							"uuid": "V1",
							"name": "Personal",
							"type": "P",
						},
						"items": []map[string]interface{}{
							{
								"uuid":         "i1",
								"categoryUuid": "001",
								"state":        "active",
								"overview": map[string]interface{}{
									"title": "GitHub",
									"url":   "https://github.com",
									"tags":  []string{"dev"},
								},
								"details": map[string]interface{}{
									"loginFields": []map[string]interface{}{
										{"designation": "username", "value": "octocat"},
										{"designation": "password", "value": "ghpass123"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	jsonData, _ := json.Marshal(data)

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.1pux")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create temp zip: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	aw, _ := zw.Create("export.attributes")
	_, _ = aw.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export"}`))

	dw, _ := zw.Create("export.data")
	_, _ = dw.Write(jsonData)

	_ = zw.Close()
	return zipPath
}

func TestSecretImportCmd_DryRun(t *testing.T) {
	zipPath := createSyntheticTestZip(t)

	viper.Set("organization_id", "org-test-123")
	viper.Set("workspace_id", "ws-test-456")
	defer func() {
		viper.Set("organization_id", "")
		viper.Set("workspace_id", "")
	}()

	cmd := secretImportCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	_ = cmd.Flags().Set("dry-run", "true")
	_ = cmd.Flags().Set("format", "1pux")
	defer func() {
		_ = cmd.Flags().Set("dry-run", "false")
		_ = cmd.Flags().Set("format", "auto")
	}()

	err := runSecretImport(cmd, []string{zipPath})
	if err != nil {
		t.Fatalf("expected dry-run to succeed, got error: %v", err)
	}
}

func TestSecretImportCmd_MissingContext(t *testing.T) {
	zipPath := createSyntheticTestZip(t)

	viper.Set("organization_id", "")
	viper.Set("workspace_id", "")

	cmd := secretImportCmd
	_ = cmd.Flags().Set("dry-run", "true")
	_ = cmd.Flags().Set("organization-id", "")
	_ = cmd.Flags().Set("workspace-id", "")
	defer func() {
		_ = cmd.Flags().Set("dry-run", "false")
	}()

	err := runSecretImport(cmd, []string{zipPath})
	if err == nil {
		t.Fatal("expected error due to missing context, got nil")
	}
}
