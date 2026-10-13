package lastpass

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

func parseCSV(t *testing.T, content string, opts importers.ImportOptions) (*importers.ImportResult, error) {
	t.Helper()

	r := bytes.NewReader([]byte(content))
	return NewCSVImporter().Parse(r, int64(len(content)), opts)
}

func decodeFlatPayload(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not a flat string map: %v (payload=%s)", err, payload)
	}
	return decoded
}

func decodeKeysValuesPayload(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	var decoded struct {
		KeysValues map[string]string `json:"keysValues"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not a keysValues map: %v (payload=%s)", err, payload)
	}
	return decoded.KeysValues
}

func findSecret(secrets []importers.ImportedSecret, name string) (importers.ImportedSecret, bool) {
	for _, s := range secrets {
		if s.Name == name {
			return s, true
		}
	}
	return importers.ImportedSecret{}, false
}

func TestCSVImporter_MatchHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{
			name:    "valid standard lastpass export",
			headers: []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"},
			want:    true,
		},
		{
			name:    "valid older export without totp",
			headers: []string{"url", "username", "password", "extra", "name", "grouping", "fav"},
			want:    true,
		},
		{
			name:    "valid export without fav",
			headers: []string{"url", "username", "password", "extra", "name", "grouping"},
			want:    true,
		},
		{
			name:    "case insensitive and trimmed headers",
			headers: []string{" URL ", "UserName", "Password", "EXTRA", " Name ", "Grouping"},
			want:    true,
		},
		{
			name:    "invalid non-lastpass - 1password csv",
			headers: []string{"title", "url", "username", "password", "otp", "notes"},
			want:    false,
		},
		{
			name:    "invalid non-lastpass - bitwarden csv",
			headers: []string{"folder", "favorite", "type", "name", "notes", "fields", "login_uri", "login_username", "login_password", "login_totp"},
			want:    false,
		},
		{
			name:    "missing grouping",
			headers: []string{"url", "username", "password", "extra", "name", "fav"},
			want:    false,
		},
		{
			name:    "missing name",
			headers: []string{"url", "username", "password", "extra", "grouping", "fav"},
			want:    false,
		},
	}

	importer := NewCSVImporter()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := importer.MatchHeaders(tc.headers); got != tc.want {
				t.Errorf("MatchHeaders(%v) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

func TestCSVImporter_ParseLoginWithCompanion2FA(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`https://github.com,octocat,gh-secret,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP,work login,GitHub,Work\Dev,1`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	login, ok := findSecret(res.Secrets, "GitHub")
	if !ok {
		t.Fatalf("primary secret 'GitHub' not found in %v", res.Secrets)
	}
	if login.Type != importers.TypeLoginPassword {
		t.Errorf("expected LOGIN_PASSWORD, got %s", login.Type)
	}
	if login.URL != "https://github.com" {
		t.Errorf("expected URL 'https://github.com', got %q", login.URL)
	}
	if login.Notes != "work login" {
		t.Errorf("expected Notes 'work login', got %q", login.Notes)
	}
	if !slices.Equal(login.Labels, []string{`Work\Dev`, "favorite"}) {
		t.Errorf("unexpected labels: %v", login.Labels)
	}
	loginPayload := decodeFlatPayload(t, login.Payload)
	if loginPayload["login"] != "octocat" || loginPayload["password"] != "gh-secret" {
		t.Errorf("unexpected login payload: %+v", loginPayload)
	}

	totp, ok := findSecret(res.Secrets, "GitHub 2FA")
	if !ok {
		t.Fatalf("companion secret 'GitHub 2FA' not found in %v", res.Secrets)
	}
	if totp.Type != importers.TypeTwoFactor {
		t.Errorf("expected TWO_FACTOR, got %s", totp.Type)
	}
	if totp.URL != "https://github.com" {
		t.Errorf("expected companion to inherit URL, got %q", totp.URL)
	}
	if !slices.Equal(totp.Labels, []string{`Work\Dev`, "favorite"}) {
		t.Errorf("expected companion to inherit labels, got %v", totp.Labels)
	}
	totpPayload := decodeFlatPayload(t, totp.Payload)
	if totpPayload["securityCode"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected securityCode 'JBSWY3DPEHPK3PXP', got %q", totpPayload["securityCode"])
	}
}

func TestCSVImporter_StructuredNoteWithMultilineValues(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		"http://sn,,,,\"NoteType:Server\nHostname:h1\nNotes:line one\nline two\nline three\",Database Server,Infrastructure,0",
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	server, ok := findSecret(res.Secrets, "Database Server")
	if !ok {
		t.Fatalf("secret 'Database Server' not found in %+v", res.Secrets)
	}
	if server.Type != importers.TypeKeysValues {
		t.Errorf("expected KEYS_VALUES, got %s", server.Type)
	}
	if server.URL != "" {
		t.Errorf("expected http://sn to be stripped, got %q", server.URL)
	}
	if server.Notes != "" {
		t.Errorf("expected Notes to be empty for KEYS_VALUES, got %q", server.Notes)
	}
	if !slices.Equal(server.Labels, []string{"Infrastructure"}) {
		t.Errorf("expected labels ['Infrastructure'], got %v", server.Labels)
	}

	kv := decodeKeysValuesPayload(t, server.Payload)
	if kv["NoteType"] != "Server" {
		t.Errorf("expected NoteType 'Server', got %q", kv["NoteType"])
	}
	if kv["Hostname"] != "h1" {
		t.Errorf("expected Hostname 'h1', got %q", kv["Hostname"])
	}
	wantNotes := "line one\nline two\nline three"
	if kv["Notes"] != wantNotes {
		t.Errorf("multiline Notes value truncated or corrupted:\ngot:  %q\nwant: %q", kv["Notes"], wantNotes)
	}
}

func TestCSVImporter_StructuredNoteWithColonBearingNotes(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		"http://sn,,,,\"NoteType:Server\nHostname:h1\nNotes:call ops first\nSee runbook: https://wiki.example/db\nthen escalate\",Prod Box,Ops,0",
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	server, ok := findSecret(res.Secrets, "Prod Box")
	if !ok {
		t.Fatalf("secret 'Prod Box' not found in %+v", res.Secrets)
	}
	kv := decodeKeysValuesPayload(t, server.Payload)
	if kv["NoteType"] != "Server" || kv["Hostname"] != "h1" {
		t.Errorf("unexpected header keys: %+v", kv)
	}
	wantNotes := "call ops first\nSee runbook: https://wiki.example/db\nthen escalate"
	if kv["Notes"] != wantNotes {
		t.Errorf("colon-bearing notes incorrectly parsed into extra keys:\ngot:  %q\nwant: %q", kv["Notes"], wantNotes)
	}
}

func TestCSVImporter_DuplicateKeysPreserveFirstValue(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		"http://sn,,,,\"NoteType:Server\nHost:first\nHost:second\",Dupe Server,Ops,0",
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	server, ok := findSecret(res.Secrets, "Dupe Server")
	if !ok {
		t.Fatalf("secret 'Dupe Server' not found in %+v", res.Secrets)
	}
	kv := decodeKeysValuesPayload(t, server.Payload)
	if kv["Host"] != "first" {
		t.Errorf("duplicate key Host = %q, want 'first' (first value must be preserved)", kv["Host"])
	}
}

func TestCSVImporter_FreeformNote(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		"https://sn,,,,\"multiline\nfreeform\nnote\",Server Runbook,Infrastructure,0",
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	note, ok := findSecret(res.Secrets, "Server Runbook")
	if !ok {
		t.Fatalf("secret 'Server Runbook' not found in %+v", res.Secrets)
	}
	if note.Type != importers.TypeSecurityNotes {
		t.Errorf("expected SECURITY_NOTES, got %s", note.Type)
	}
	if note.URL != "" {
		t.Errorf("expected https://sn to be stripped, got %q", note.URL)
	}
	if note.Notes != "" {
		t.Errorf("expected Notes empty for SECURITY_NOTES, got %q", note.Notes)
	}
	notePayload := decodeFlatPayload(t, note.Payload)
	if notePayload["securityNotes"] != "multiline\nfreeform\nnote" {
		t.Errorf("unexpected securityNotes: %+v", notePayload)
	}
}

func TestCSVImporter_MalformedTOTPSeed(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`https://bad.example,broken-user,broken-pw,INVALID_TOTP_SEED!!,broken note,Broken 2FA,Dev,0`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	broken, ok := findSecret(res.Secrets, "Broken 2FA")
	if !ok {
		t.Fatalf("secret 'Broken 2FA' not found in %+v", res.Secrets)
	}
	if broken.Type != importers.TypeLoginPassword {
		t.Errorf("expected LOGIN_PASSWORD, got %s", broken.Type)
	}

	if len(res.Warnings) == 0 {
		t.Fatal("expected warning for invalid TOTP seed")
	}
	if !strings.Contains(res.Warnings[0], "line 2:") || !strings.Contains(res.Warnings[0], "Broken 2FA") {
		t.Errorf("warning should name line 2 and Broken 2FA: %q", res.Warnings[0])
	}
}

func TestCSVImporter_InvalidURLStripped(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`not-a-valid-url,apiuser,apipw,,,Bad URL Service,,0`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	secret, ok := findSecret(res.Secrets, "Bad URL Service")
	if !ok {
		t.Fatalf("secret 'Bad URL Service' not found in %+v", res.Secrets)
	}
	if secret.URL != "" {
		t.Errorf("expected invalid URL stripped, got %q", secret.URL)
	}
}

func TestCSVImporter_UntitledRow(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`,user,pw,,,,Personal,0`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Untitled Secret" {
		t.Fatalf("expected 'Untitled Secret', got %+v", res.Secrets)
	}
}

func TestCSVImporter_SparseRowWarns(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`https://example.com,user,pw,,,Valid Item,Dev,0`,
		`https://empty.example,,,,,Empty Item,Dev,0`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Valid Item" {
		t.Fatalf("expected only 'Valid Item' to import, got %+v", res.Secrets)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "line 3:") || !strings.Contains(res.Warnings[0], "Empty Item") {
		t.Errorf("expected sparse row warning on line 3, got %v", res.Warnings)
	}
}

func TestCSVImporter_VaultFilter(t *testing.T) {
	content := strings.Join([]string{
		"url,username,password,totp,extra,name,grouping,fav",
		`https://app1.example,user1,pw1,,,App 1,Engineering\Backend,0`,
		`https://app2.example,user2,pw2,,,App 2,Engineering\Frontend,0`,
		`https://app3.example,user3,pw3,,,App 3,Marketing,0`,
	}, "\n")

	res, err := parseCSV(t, content, importers.ImportOptions{VaultFilter: "Engineering"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("expected 2 secrets matching 'Engineering', got %d", len(res.Secrets))
	}
	if res.Secrets[0].Name != "App 1" || res.Secrets[1].Name != "App 2" {
		t.Errorf("unexpected secrets: %+v", res.Secrets)
	}

	// Specific sub-vault with forward slash
	resSub, err := parseCSV(t, content, importers.ImportOptions{VaultFilter: `Engineering/Backend`})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(resSub.Secrets) != 1 || resSub.Secrets[0].Name != "App 1" {
		t.Errorf("expected App 1 for Engineering/Backend, got %+v", resSub.Secrets)
	}
}

func TestCSVImporter_EmptyExport(t *testing.T) {
	content := "url,username,password,totp,extra,name,grouping,fav\n"
	_, err := parseCSV(t, content, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
}
