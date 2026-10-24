package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	aw, _ := zw.Create("export.attributes")
	_, _ = aw.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export"}`))

	dw, _ := zw.Create("export.data")
	_, _ = dw.Write(jsonData)

	_ = zw.Close()
	return zipPath
}

// runImport builds a fresh secret command tree, runs `secret import` with args,
// and returns everything the command wrote. A new tree per call keeps flag
// state from leaking between tests.
func runImport(t *testing.T, args ...string) (string, error) {
	t.Helper()

	root := newSecretCmd()
	root.AddCommand(newSecretImportCmd())

	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"import"}, args...))

	err := root.Execute()
	return buf.String(), err
}

// runImportDryRun asserts the dry run succeeds and returns its output.
func runImportDryRun(t *testing.T, path string, extraFlags map[string]string) string {
	t.Helper()

	viper.Set("organization_id", "org-test-123")
	viper.Set("workspace_id", "ws-test-456")
	t.Cleanup(func() {
		viper.Set("organization_id", "")
		viper.Set("workspace_id", "")
	})

	args := []string{path, "--dry-run"}
	for name, value := range extraFlags {
		args = append(args, "--"+name+"="+value)
	}

	out, err := runImport(t, args...)
	if err != nil {
		t.Fatalf("expected dry-run to succeed, got error: %v\n%s", err, out)
	}
	return out
}

func writeTempCSV(t *testing.T, rows string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secrets.csv")
	if err := os.WriteFile(path, []byte(rows), 0o600); err != nil {
		t.Fatalf("failed to write temp csv: %v", err)
	}
	return path
}

func TestSecretImportCmd_DryRun(t *testing.T) {
	out := runImportDryRun(t, createSyntheticTestZip(t), map[string]string{"format": "1pux"})

	for _, want := range []string{"Detected format: 1Password", "GitHub", "LOGIN_PASSWORD"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
}

func TestSecretImportCmd_VaultIgnoredForCSVProviders(t *testing.T) {
	csvPath := writeTempCSV(t, `Name,Type,Value,Login,Password
GitHub,LOGIN_PASSWORD,,octocat,ghpass123
Ops Note,SECURITY_NOTES,rotate quarterly,,
`)

	out := runImportDryRun(t, csvPath, map[string]string{"vault": "Dev"})

	if !strings.Contains(out, `--vault "Dev" ignored`) {
		t.Errorf("output must warn that the filter was dropped:\n%s", out)
	}
	if !strings.Contains(out, "scope: entire file, --vault ignored") {
		t.Errorf("banner must report the effective scope, not the requested one:\n%s", out)
	}
	// The filter is dropped, not half-applied: nothing may be filtered out.
	for _, want := range []string{"GitHub", "Ops Note", "Found 2 secret(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestSecretImportCmd_VaultHonoredFor1PUX(t *testing.T) {
	out := runImportDryRun(t, createSyntheticTestZip(t), map[string]string{
		"format": "1pux",
		"vault":  "Personal",
	})

	if strings.Contains(out, "ignored") {
		t.Errorf("1PUX supports vault filtering and must not warn:\n%s", out)
	}
	if !strings.Contains(out, `scope: vault "Personal"`) {
		t.Errorf("banner must name the honored vault:\n%s", out)
	}
	if !strings.Contains(out, "GitHub") {
		t.Errorf("expected the Personal vault secret in the preview:\n%s", out)
	}
}

func TestSecretImportCmd_ScopeWordingPerFormat(t *testing.T) {
	csvPath := writeTempCSV(t, "Name,Type,Value\nToken,SECURITY_NOTES,abc\n")

	// A CSV has no vaults, so the banner must not claim it scanned "all vaults".
	csvOut := runImportDryRun(t, csvPath, nil)
	if !strings.Contains(csvOut, "scope: entire file") {
		t.Errorf("CSV banner = missing 'scope: entire file':\n%s", csvOut)
	}
	if strings.Contains(csvOut, "all vaults") {
		t.Errorf("CSV banner must not mention vaults:\n%s", csvOut)
	}

	puxOut := runImportDryRun(t, createSyntheticTestZip(t), map[string]string{"format": "1pux"})
	if !strings.Contains(puxOut, "scope: all vaults") {
		t.Errorf("1PUX banner = missing 'scope: all vaults':\n%s", puxOut)
	}
}

func TestSecretImportCmd_DryRunDeduplicatesTitles(t *testing.T) {
	csvPath := writeTempCSV(t, `Name,Type,Value,Login,Password
Duplicate,LOGIN_PASSWORD,,first,pw1
Duplicate,LOGIN_PASSWORD,,second,pw2
Duplicate,LOGIN_PASSWORD,,third,pw3
`)

	out := runImportDryRun(t, csvPath, nil)

	// Deduplication must run before the preview, or the dry run would advertise
	// names the live import will not create.
	for _, want := range []string{"Duplicate ", "Duplicate-1", "Duplicate-2"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Duplicate-3") {
		t.Errorf("suffixes must start at -1:\n%s", out)
	}
}

func TestSecretImportCmd_DryRunCSV(t *testing.T) {
	csvPath := writeTempCSV(t, `Name,Type,Value,Login,Password,URL,Labels
GitHub,LOGIN_PASSWORD,,octocat,ghpass123,https://github.com,dev
Deploy Keys,KEYS_VALUES,"apiKey: abc123
region: eu-west-1",,,,infra
Recovery Note,SECURITY_NOTES,keep this offline,,,,
`)

	out := runImportDryRun(t, csvPath, map[string]string{"format": "csv"})

	for _, want := range []string{
		"Detected format: Generic CSV",
		"Found 3 secret(s)",
		"GitHub",
		"Deploy Keys",
		"Recovery Note",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("csv dry-run output missing %q\n%s", want, out)
		}
	}
}

func TestSecretImportCmd_DryRunCapsListing(t *testing.T) {
	const rowCount = 60

	var sb strings.Builder
	sb.WriteString("Name,Type,Value,Login,Password,URL,Labels\n")
	for i := 1; i <= rowCount; i++ {
		fmt.Fprintf(&sb, "Secret %d,LOGIN_PASSWORD,,user%d,pass%d,,\n", i, i, i)
	}
	csvPath := writeTempCSV(t, sb.String())

	capped := runImportDryRun(t, csvPath, map[string]string{"format": "csv"})
	if !strings.Contains(capped, "... and 10 more secrets (use --verbose to show all)") {
		t.Errorf("expected capped listing with overflow line, got:\n%s", capped)
	}
	if strings.Contains(capped, "Secret 60") {
		t.Errorf("capped listing leaked row 60:\n%s", capped)
	}

	full := runImportDryRun(t, csvPath, map[string]string{"format": "csv", "verbose": "true"})
	if strings.Contains(full, "more secrets") {
		t.Errorf("--verbose output should not be capped, got:\n%s", full)
	}
	if !strings.Contains(full, "Secret 60") {
		t.Errorf("--verbose output missing last row:\n%s", full)
	}
}

func TestSecretImportCmd_DryRunCapsWarnings(t *testing.T) {
	const rowCount = 25

	var sb strings.Builder
	sb.WriteString("Name,Type,Value,Login,Password,URL,Labels\n")
	for i := 1; i <= rowCount; i++ {
		fmt.Fprintf(&sb, "Secret %d,MYSTERY_TYPE,,user%d,pass%d,,\n", i, i, i)
	}
	csvPath := writeTempCSV(t, sb.String())

	capped := runImportDryRun(t, csvPath, map[string]string{"format": "csv"})
	if !strings.Contains(capped, "Warnings (25):") {
		t.Errorf("expected warning count header, got:\n%s", capped)
	}
	if !strings.Contains(capped, "... and 5 more warnings (use --verbose to show all)") {
		t.Errorf("expected capped warnings with overflow line, got:\n%s", capped)
	}

	full := runImportDryRun(t, csvPath, map[string]string{"format": "csv", "verbose": "true"})
	if strings.Contains(full, "more warnings") {
		t.Errorf("--verbose warnings should not be capped, got:\n%s", full)
	}
	if got := strings.Count(full, `unknown type "MYSTERY_TYPE"`); got != rowCount {
		t.Errorf("expected %d warnings under --verbose, got %d:\n%s", rowCount, got, full)
	}
}

func TestSecretImportCmd_MissingContext(t *testing.T) {
	zipPath := createSyntheticTestZip(t)

	viper.Set("organization_id", "")
	viper.Set("workspace_id", "")

	if _, err := runImport(t, zipPath, "--dry-run"); err == nil {
		t.Fatal("expected error due to missing context, got nil")
	}
}

func TestSecretImportCmd_DryRunLastPassCSV(t *testing.T) {
	csvPath := writeTempCSV(t, `url,username,password,totp,extra,name,grouping,fav
https://lastpass.example,user,pw,JBSWY3DPEHPK3PXP,note,LP Service,Work\Prod,1
http://sn,,,,"NoteType:Server
Host:1.2.3.4",My Server,Work,0
`)

	out := runImportDryRun(t, csvPath, map[string]string{"format": "auto", "vault": "Work"})

	for _, want := range []string{
		"Detected format: LastPass CSV",
		`scope: vault "Work"`,
		"Found 3 secret(s)",
		"LP Service",
		"LP Service 2FA",
		"My Server",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("LastPass dry-run output missing %q\n%s", want, out)
		}
	}
}

func TestSecretImportCmd_DryRunBitwardenCSV(t *testing.T) {
	csvPath := writeTempCSV(t, `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,BW Service,BW Note,"API: key123",0,https://bitwarden.example.com,bwuser,bwpw,JBSWY3DPEHPK3PXP
Work,,note,BW Secure Note,Keep safe.,,0,,,,
Personal,,login,Personal Acct,,,0,,puser,ppw,
`)

	out := runImportDryRun(t, csvPath, map[string]string{"format": "auto", "vault": "Work"})

	for _, want := range []string{
		"Detected format: Bitwarden CSV",
		`scope: vault "Work"`,
		"Found 3 secret(s)",
		"BW Service",
		"BW Service 2FA",
		"BW Secure Note",
		"LOGIN_PASSWORD : 1",
		"SECURITY_NOTES : 1",
		"TWO_FACTOR     : 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Bitwarden dry-run output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "Personal Acct") {
		t.Errorf("Personal Acct should have been filtered out by --vault Work:\n%s", out)
	}
}
