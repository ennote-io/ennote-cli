package ennote

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

func parse(t *testing.T, data string) *importers.ImportResult {
	t.Helper()

	result, err := NewCSVImporter().Parse(strings.NewReader(data), int64(len(data)), importers.ImportOptions{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return result
}

func secretByName(t *testing.T, result *importers.ImportResult, name string) importers.ImportedSecret {
	t.Helper()

	for _, s := range result.Secrets {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("secret %q not found in %d secrets", name, len(result.Secrets))
	return importers.ImportedSecret{}
}

func payloadStrings(t *testing.T, secret importers.ImportedSecret) map[string]string {
	t.Helper()

	var decoded map[string]string
	if err := json.Unmarshal(secret.Payload, &decoded); err != nil {
		t.Fatalf("payload of %q is not a flat string object (%s): %v", secret.Name, secret.Payload, err)
	}
	return decoded
}

func keysValues(t *testing.T, secret importers.ImportedSecret) map[string]string {
	t.Helper()

	var decoded struct {
		KeysValues map[string]string `json:"keysValues"`
	}
	if err := json.Unmarshal(secret.Payload, &decoded); err != nil {
		t.Fatalf("payload of %q is not {keysValues: flat map} (%s): %v", secret.Name, secret.Payload, err)
	}
	return decoded.KeysValues
}

func warningsContaining(result *importers.ImportResult, needle string) []string {
	var hits []string
	for _, w := range result.Warnings {
		if strings.Contains(w, needle) {
			hits = append(hits, w)
		}
	}
	return hits
}

func TestMatchHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{"native export", []string{"Name", "Type", "Value", "URL", "Labels", "Notes"}, true},
		{"title with credentials", []string{"title", "login", "password"}, true},
		{"case and space insensitive", []string{" NAME ", " Keys_Values "}, true},
		{"generic csv with payload column", []string{"name", "payload"}, true},
		{"no name column", []string{"login", "password", "url"}, false},
		{"name without any value column", []string{"name", "url", "notes"}, false},
		{"empty headers", nil, false},
	}

	importer := NewCSVImporter()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importer.MatchHeaders(tt.headers); got != tt.want {
				t.Errorf("MatchHeaders(%v) = %v, want %v", tt.headers, got, tt.want)
			}
		})
	}
}

func TestParseAllTypes(t *testing.T) {
	data := "Name,Type,Value,Login,Password,URL,Labels,Notes\n" +
		"AWS Console,LOGIN_PASSWORD,,admin,s3cret,https://console.aws.amazon.com,\"cloud, prod\",root account\n" +
		"Service Env,keys_values,\"API_KEY=abc123\nREGION=us-east-1\",,,,dev;ci,\n" +
		"Recovery,SECURITY_NOTES,keep offline,,,,,paper backup\n" +
		"Vault OTP,two_factor,JBSWY3DPEHPK3PXP,,,,,\n"

	result := parse(t, data)

	if len(result.Secrets) != 4 {
		t.Fatalf("got %d secrets, want 4 (warnings: %v)", len(result.Secrets), result.Warnings)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", result.Warnings)
	}

	login := secretByName(t, result, "AWS Console")
	if login.Type != importers.TypeLoginPassword {
		t.Errorf("AWS Console type = %s, want %s", login.Type, importers.TypeLoginPassword)
	}
	if got := payloadStrings(t, login); got["login"] != "admin" || got["password"] != "s3cret" || len(got) != 2 {
		t.Errorf("login payload = %v, want {login:admin password:s3cret}", got)
	}
	if login.URL != "https://console.aws.amazon.com" {
		t.Errorf("URL = %q", login.URL)
	}
	if login.Notes != "root account" {
		t.Errorf("Notes = %q", login.Notes)
	}
	if got := login.Labels; len(got) != 2 || got[0] != "cloud" || got[1] != "prod" {
		t.Errorf("Labels = %v, want [cloud prod]", got)
	}

	kv := secretByName(t, result, "Service Env")
	if kv.Type != importers.TypeKeysValues {
		t.Errorf("Service Env type = %s, want %s", kv.Type, importers.TypeKeysValues)
	}
	pairs := keysValues(t, kv)
	if pairs["API_KEY"] != "abc123" || pairs["REGION"] != "us-east-1" || len(pairs) != 2 {
		t.Errorf("keysValues = %v", pairs)
	}
	if got := kv.Labels; len(got) != 2 || got[0] != "dev" || got[1] != "ci" {
		t.Errorf("semicolon labels = %v, want [dev ci]", got)
	}

	notes := secretByName(t, result, "Recovery")
	if notes.Type != importers.TypeSecurityNotes {
		t.Errorf("Recovery type = %s, want %s", notes.Type, importers.TypeSecurityNotes)
	}
	if got := payloadStrings(t, notes); got["securityNotes"] != "keep offline" || len(got) != 1 {
		t.Errorf("notes payload = %v", got)
	}

	otp := secretByName(t, result, "Vault OTP")
	if otp.Type != importers.TypeTwoFactor {
		t.Errorf("Vault OTP type = %s, want %s", otp.Type, importers.TypeTwoFactor)
	}
	if got := payloadStrings(t, otp); got["securityCode"] != "JBSWY3DPEHPK3PXP" || len(got) != 1 {
		t.Errorf("2FA payload = %v", got)
	}
}

func TestParseInfersTypeFromColumns(t *testing.T) {
	data := "Name,Type,Value,Login,Password\n" +
		"Router,,,root,toor\n" +
		"Config,,\"HOST=db.local\nPORT=5432\",,\n" +
		"Memo,,rotate the key every quarter,,\n"

	result := parse(t, data)

	if len(result.Warnings) != 0 {
		t.Errorf("inference should not warn: %v", result.Warnings)
	}

	if got := secretByName(t, result, "Router").Type; got != importers.TypeLoginPassword {
		t.Errorf("Router type = %s, want %s", got, importers.TypeLoginPassword)
	}
	if got := secretByName(t, result, "Config").Type; got != importers.TypeKeysValues {
		t.Errorf("Config type = %s, want %s", got, importers.TypeKeysValues)
	}
	memo := secretByName(t, result, "Memo")
	if memo.Type != importers.TypeSecurityNotes {
		t.Errorf("Memo type = %s, want %s", memo.Type, importers.TypeSecurityNotes)
	}
	if got := payloadStrings(t, memo)["securityNotes"]; got != "rotate the key every quarter" {
		t.Errorf("Memo securityNotes = %q", got)
	}
}

func TestParseExplicitTypeOverridesInference(t *testing.T) {
	data := "Name,Type,Value,Login,Password\n" +
		"Shared Host,SECURITY_NOTES,ask ops for access,root,toor\n"

	secret := secretByName(t, parse(t, data), "Shared Host")

	if secret.Type != importers.TypeSecurityNotes {
		t.Fatalf("type = %s, want %s despite login/password columns", secret.Type, importers.TypeSecurityNotes)
	}
	if got := payloadStrings(t, secret); got["securityNotes"] != "ask ops for access" || len(got) != 1 {
		t.Errorf("payload = %v", got)
	}
}

func TestParseUnknownTypeWarnsAndImports(t *testing.T) {
	data := "Name,Type,Value,Login,Password\n" +
		"Wifi,WIFI_PASSWORD,,guest,hunter2\n"

	result := parse(t, data)
	secret := secretByName(t, result, "Wifi")

	if secret.Type != importers.TypeLoginPassword {
		t.Errorf("type = %s, want inferred %s", secret.Type, importers.TypeLoginPassword)
	}
	if got := payloadStrings(t, secret)["password"]; got != "hunter2" {
		t.Errorf("password = %q", got)
	}

	hits := warningsContaining(result, `unknown type "WIFI_PASSWORD"`)
	if len(hits) != 1 {
		t.Fatalf("warnings = %v, want one unknown-type warning", result.Warnings)
	}
	if !strings.Contains(hits[0], "line 2") || !strings.Contains(hits[0], "imported as LOGIN_PASSWORD") {
		t.Errorf("warning = %q, want line number and resolved type", hits[0])
	}
}

func TestParseKeysValuesFormats(t *testing.T) {
	data := "Name,Type,Value\n" +
		"Dotenv,KEYS_VALUES,\"# comment\nTOKEN=t0k3n\nSCOPE=read\"\n" +
		"Json,KEYS_VALUES,\"{\"\"host\"\":\"\"db.local\"\",\"\"port\"\":5432,\"\"tls\"\":{\"\"enabled\"\":true}}\"\n" +
		"Prose,KEYS_VALUES,no pairs in here\n"

	result := parse(t, data)

	dotenv := keysValues(t, secretByName(t, result, "Dotenv"))
	if dotenv["TOKEN"] != "t0k3n" || dotenv["SCOPE"] != "read" || len(dotenv) != 2 {
		t.Errorf("dotenv keysValues = %v", dotenv)
	}

	jsonKV := keysValues(t, secretByName(t, result, "Json"))
	if jsonKV["host"] != "db.local" || jsonKV["port"] != "5432" {
		t.Errorf("json keysValues = %v", jsonKV)
	}
	if jsonKV["tls"] != `{"enabled":true}` {
		t.Errorf("nested object = %q, want compact JSON string", jsonKV["tls"])
	}

	prose := secretByName(t, result, "Prose")
	if prose.Type != importers.TypeSecurityNotes {
		t.Errorf("pairless value type = %s, want %s", prose.Type, importers.TypeSecurityNotes)
	}
	if got := payloadStrings(t, prose)["securityNotes"]; got != "no pairs in here" {
		t.Errorf("fallback securityNotes = %q", got)
	}
	if hits := warningsContaining(result, "no key/value pairs"); len(hits) != 1 {
		t.Errorf("warnings = %v, want one key/value fallback warning", result.Warnings)
	}
}

func TestParseKeysValuesPreservesShellUnsafeKeys(t *testing.T) {
	data := "Name,Type,Value\n" +
		"Wifi Note,KEYS_VALUES,\"Network Name: CorpNet\nPassword: hunter2\"\n"

	result := parse(t, data)

	kv := keysValues(t, secretByName(t, result, "Wifi Note"))
	if kv["Network Name"] != "CorpNet" {
		t.Errorf("keys must be preserved verbatim, got %v", kv)
	}
	if _, renamed := kv["Network_Name"]; renamed {
		t.Errorf("key was renamed: %v", kv)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("a key with a space is not an import problem, got warnings %v", result.Warnings)
	}
}

func TestParseSkipsUnusableRows(t *testing.T) {
	data := "Name,Type,Value,Login,Password\n" +
		"Broken 2FA,TWO_FACTOR,not-a-seed!,,\n" +
		"Empty Row,LOGIN_PASSWORD,,,\n" +
		"Good,TWO_FACTOR,otpauth://totp/Ennote:me?secret=JBSWY3DPEHPK3PXP&issuer=Ennote,,\n"

	result := parse(t, data)

	if len(result.Secrets) != 1 {
		t.Fatalf("got %d secrets, want only the valid one: %+v", len(result.Secrets), result.Secrets)
	}
	if got := payloadStrings(t, result.Secrets[0])["securityCode"]; got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("securityCode = %q, want seed extracted from otpauth URI", got)
	}

	if hits := warningsContaining(result, `"Broken 2FA"`); len(hits) != 1 || !strings.Contains(hits[0], "line 2") {
		t.Errorf("warnings = %v, want a line-2 warning naming the malformed seed row", result.Warnings)
	}
	if hits := warningsContaining(result, `"Empty Row"`); len(hits) != 1 {
		t.Errorf("warnings = %v, want a warning for the payload-less row", result.Warnings)
	}
}

func TestParseDropsInvalidURLAndDefaultsName(t *testing.T) {
	data := "Name,Type,Value,URL\n" +
		",SECURITY_NOTES,orphan note,not a url at all\n"

	secret := parse(t, data).Secrets[0]

	if secret.Name != "Untitled Secret" {
		t.Errorf("Name = %q, want %q", secret.Name, "Untitled Secret")
	}
	if secret.URL != "" {
		t.Errorf("URL = %q, want invalid endpoint dropped", secret.URL)
	}
}

func TestParseEmptyExport(t *testing.T) {
	data := "Name,Type,Value,Login,Password\n,,,,\n,,,,\n"

	_, err := NewCSVImporter().Parse(strings.NewReader(data), int64(len(data)), importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("Parse() error = %v, want %v", err, importers.ErrEmptyExport)
	}
}

func TestParseKeysValuesMultilineContinuation(t *testing.T) {
	data := "Name,Type,Value\n" +
		"Box,KEYS_VALUES,\"Host:h1\nNotes:line one\nline two\"\n"

	secret := secretByName(t, parse(t, data), "Box")
	kv := keysValues(t, secret)

	if kv["Host"] != "h1" {
		t.Errorf("Host = %q, want h1", kv["Host"])
	}
	if kv["Notes"] != "line one\nline two" {
		t.Errorf("Notes = %q, want 'line one\\nline two'", kv["Notes"])
	}
}
