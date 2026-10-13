package onepassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

func parseCSV(t *testing.T, content string) (*importers.ImportResult, error) {
	t.Helper()

	r := bytes.NewReader([]byte(content))
	return NewCSVImporter().Parse(r, int64(len(content)), importers.ImportOptions{})
}

func decodePayload(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("payload is not a flat string map: %v (payload=%s)", err, payload)
	}
	return decoded
}

func TestCSVImporter_MatchHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{
			name:    "1password export",
			headers: []string{"title", "url", "username", "password", "otp", "notes"},
			want:    true,
		},
		{
			name:    "1password 8 export",
			headers: []string{"Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes"},
			want:    true,
		},
		{
			name:    "lastpass grouping column",
			headers: []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav", "title"},
			want:    false,
		},
		{
			name:    "bitwarden folder column",
			headers: []string{"folder", "favorite", "type", "title", "notes", "login_uri", "password"},
			want:    false,
		},
		{
			name:    "no password column",
			headers: []string{"title", "url", "notes"},
			want:    false,
		},
		{
			name:    "no title column",
			headers: []string{"name", "username", "password"},
			want:    false,
		},
		{
			name:    "mixed case and padding",
			headers: []string{" Title ", "Username", "PASSWORD"},
			want:    true,
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

func TestCSVImporter_ParseRows(t *testing.T) {
	content := strings.Join([]string{
		"Title,Url,Username,Password,OTP,Notes",
		"Example Login,https://login.example.com,testuser@example.com,SecretPass123!,otpauth://totp/Example:testuser?secret=JBSWY3DPEHPK3PXP&issuer=Example,login note",
		"Runbook,,,,,\"# Deployment\nStep one\"",
		"Broken 2FA,,someone,pw,not-base32!!,",
		"Bad URL,not a url,user2,pw2,,",
		",,,,,",
	}, "\n")

	res, err := parseCSV(t, content)
	if err != nil {
		t.Fatalf("unexpected error parsing 1Password CSV: %v", err)
	}

	names := make([]string, 0, len(res.Secrets))
	for _, s := range res.Secrets {
		names = append(names, s.Name)
	}
	want := []string{"Example Login", "Example Login 2FA", "Runbook", "Broken 2FA", "Bad URL"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected secrets %v, want %v", names, want)
	}

	login := res.Secrets[0]
	if login.Type != importers.TypeLoginPassword {
		t.Errorf("expected LOGIN_PASSWORD, got %s", login.Type)
	}
	if login.URL != "https://login.example.com" {
		t.Errorf("expected URL kept, got %q", login.URL)
	}
	if login.Notes != "login note" {
		t.Errorf("expected notes on secret, got %q", login.Notes)
	}
	loginPayload := decodePayload(t, login.Payload)
	if loginPayload["login"] != "testuser@example.com" || loginPayload["password"] != "SecretPass123!" {
		t.Errorf("unexpected login payload: %+v", loginPayload)
	}

	totp := res.Secrets[1]
	if totp.Type != importers.TypeTwoFactor {
		t.Errorf("expected TWO_FACTOR companion, got %s", totp.Type)
	}
	if code := decodePayload(t, totp.Payload)["securityCode"]; code != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected securityCode 'JBSWY3DPEHPK3PXP', got %q", code)
	}

	note := res.Secrets[2]
	if note.Type != importers.TypeSecurityNotes {
		t.Errorf("expected SECURITY_NOTES for notes-only row, got %s", note.Type)
	}
	if notes := decodePayload(t, note.Payload)["securityNotes"]; !strings.Contains(notes, "Deployment") {
		t.Errorf("unexpected securityNotes content: %q", notes)
	}

	if res.Secrets[4].URL != "" {
		t.Errorf("expected invalid URL dropped, got %q", res.Secrets[4].URL)
	}

	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "line 4:") || !strings.Contains(res.Warnings[0], "Broken 2FA") {
		t.Fatalf("expected one malformed-seed warning for line 4, got %v", res.Warnings)
	}
}

func TestCSVImporter_UntitledRow(t *testing.T) {
	content := "Title,Username,Password\n,user,pw\n"

	res, err := parseCSV(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Untitled Secret" {
		t.Fatalf("expected a single 'Untitled Secret', got %+v", res.Secrets)
	}
}

func TestCSVImporter_ParseV8Rows(t *testing.T) {
	content := strings.Join([]string{
		"Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes",
		"Cloud Console,https://console.example.com,ops@example.com,S3cret!,otpauth://totp/Example:ops?secret=JBSWY3DPEHPK3PXP&issuer=Example,true,false,\"cloud, prod;infra\",console note",
		"Old Service,https://old.example.com,legacy@example.com,oldpw,JBSWY3DPEHPK3PXP,1,yes,archived-tag,gone",
		"Plain Note,,,,,0,,,just a note",
	}, "\n")

	res, err := parseCSV(t, content)
	if err != nil {
		t.Fatalf("unexpected error parsing 1Password 8 CSV: %v", err)
	}

	names := make([]string, 0, len(res.Secrets))
	for _, s := range res.Secrets {
		names = append(names, s.Name)
	}
	want := []string{"Cloud Console", "Cloud Console 2FA", "Plain Note"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected secrets %v, want %v (archived row must be skipped)", names, want)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", res.Warnings)
	}

	login := res.Secrets[0]
	if login.Type != importers.TypeLoginPassword {
		t.Errorf("expected LOGIN_PASSWORD, got %s", login.Type)
	}
	if login.URL != "https://console.example.com" || login.Notes != "console note" {
		t.Errorf("unexpected metadata: url=%q notes=%q", login.URL, login.Notes)
	}
	loginPayload := decodePayload(t, login.Payload)
	if loginPayload["login"] != "ops@example.com" || loginPayload["password"] != "S3cret!" {
		t.Errorf("unexpected login payload: %+v", loginPayload)
	}
	wantLabels := []string{"cloud", "prod", "infra", "favorite"}
	if strings.Join(login.Labels, "|") != strings.Join(wantLabels, "|") {
		t.Errorf("login labels = %v, want %v", login.Labels, wantLabels)
	}

	totp := res.Secrets[1]
	if totp.Type != importers.TypeTwoFactor {
		t.Errorf("expected TWO_FACTOR companion, got %s", totp.Type)
	}
	if code := decodePayload(t, totp.Payload)["securityCode"]; code != "JBSWY3DPEHPK3PXP" {
		t.Errorf("expected securityCode from OTPAuth column, got %q", code)
	}
	if strings.Join(totp.Labels, "|") != strings.Join(wantLabels, "|") {
		t.Errorf("companion labels = %v, want %v", totp.Labels, wantLabels)
	}

	note := res.Secrets[2]
	if note.Type != importers.TypeSecurityNotes {
		t.Errorf("expected SECURITY_NOTES, got %s", note.Type)
	}
	if got := decodePayload(t, note.Payload)["securityNotes"]; got != "just a note" {
		t.Errorf("unexpected securityNotes: %q", got)
	}
	if note.Labels != nil {
		t.Errorf("expected nil labels without tags or favorite, got %v", note.Labels)
	}
}

func TestCSVImporter_AllRowsArchived(t *testing.T) {
	content := "Title,Username,Password,Archived\nGone,user,pw,TRUE\n"

	if _, err := parseCSV(t, content); err != importers.ErrEmptyExport {
		t.Fatalf("expected ErrEmptyExport when every row is archived, got %v", err)
	}
}

// Comma is the only delimiter, so an Excel-EU re-save is one column: the header
// carries no title/password pair and the provider declines it.
func TestCSVImporter_SemicolonDelimitedExportIsNotClaimed(t *testing.T) {
	headers := []string{"title;url;username;password;otpauth"}

	if NewCSVImporter().MatchHeaders(headers) {
		t.Errorf("MatchHeaders(%q) = true, want false", headers)
	}
}

func TestCSVImporter_EncodingAndUnicodeRows(t *testing.T) {
	// BOM, CRLF, escaped quotes, an embedded newline and non-ASCII content all
	// in one file: every value must survive byte-for-byte.
	content := "\ufeffTitle,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\r\n" +
		"\"Quoted \"\"Nickname\"\"\",https://quotes.example,user,pw-quotes,,false,false,edge,\"he said \"\"hello\"\", then left\"\r\n" +
		"Ünïcödé Ítem,https://unicode.example,ünïcödé@example.com,pässwörd,,false,false,\"i18n;ünïcödé\",émojis 🔐\r\n" +
		"Multiline Note,,,,,false,false,notes,\"line one,\nline two\"\r\n"

	res, err := parseCSV(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 3 {
		t.Fatalf("got %d secrets, want 3: %+v", len(res.Secrets), res.Secrets)
	}

	// A BOM left in place would make the first column unreadable and this row
	// would be titled "Untitled Secret".
	if got := res.Secrets[0].Name; got != `Quoted "Nickname"` {
		t.Errorf("title = %q, want escaped quotes unescaped exactly once", got)
	}
	if got := res.Secrets[0].Notes; got != `he said "hello", then left` {
		t.Errorf("notes = %q, want quotes and comma preserved", got)
	}

	unicode := res.Secrets[1]
	if unicode.Name != "Ünïcödé Ítem" || unicode.Notes != "émojis 🔐" {
		t.Errorf("unicode row mangled: name=%q notes=%q", unicode.Name, unicode.Notes)
	}
	if got := decodePayload(t, unicode.Payload); got["login"] != "ünïcödé@example.com" || got["password"] != "pässwörd" {
		t.Errorf("unicode payload mangled: %+v", got)
	}
	if got := unicode.Labels; !slices.Equal(got, []string{"i18n", "ünïcödé"}) {
		t.Errorf("labels = %v, want non-ASCII tags intact", got)
	}

	if got := decodePayload(t, res.Secrets[2].Payload)["securityNotes"]; got != "line one,\nline two" {
		t.Errorf("multiline note = %q, want the embedded newline preserved", got)
	}
}

func TestCSVImporter_EmptyRowSilentSparseRowWarns(t *testing.T) {
	content := "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n" +
		"Keeper,https://keep.example,me,pw,,false,false,,\n" +
		",,,,,,,,\n" +
		"   ,\t,,,,,,,\n" +
		"Sparse Row,https://sparse.example,,,,false,false,tagged,\n"

	res, err := parseCSV(t, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Keeper" {
		t.Fatalf("expected only the usable row to import, got %+v", res.Secrets)
	}

	// The blank lines are exporter noise; the row carrying a title, URL and tag
	// but no credentials is a row the user loses, so it must be reported.
	if len(res.Warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %v", res.Warnings)
	}
	if !strings.Contains(res.Warnings[0], `"Sparse Row"`) || !strings.Contains(res.Warnings[0], "line 5") {
		t.Errorf("warning = %q, want the sparse row named with its line", res.Warnings[0])
	}
}

func TestCSVImporter_CompanionNaming(t *testing.T) {
	// Seed-only row: the title already names it, so no suffix is added.
	seedOnly, err := parseCSV(t, "Title,Username,Password,OTPAuth\nGitHub 2FA,,,JBSWY3DPEHPK3PXP\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seedOnly.Secrets) != 1 || seedOnly.Secrets[0].Name != "GitHub 2FA" {
		t.Errorf("seed-only row = %+v, want a single %q secret", seedOnly.Secrets, "GitHub 2FA")
	}

	// Credentials plus a seed under a title ending in 2FA: the two secrets need
	// distinct names, and the suffix beats deduplication's "GitHub 2FA-1".
	both, err := parseCSV(t, "Title,Username,Password,OTPAuth\nGitHub 2FA,me,pw,JBSWY3DPEHPK3PXP\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := make([]string, len(both.Secrets))
	for i, s := range both.Secrets {
		names[i] = s.Name
	}
	if !slices.Equal(names, []string{"GitHub 2FA", "GitHub 2FA 2FA"}) {
		t.Errorf("names = %v, want distinct login and companion names", names)
	}

	// The ordinary case gains the suffix exactly once.
	plain, err := parseCSV(t, "Title,Username,Password,OTPAuth\nGitHub,me,pw,JBSWY3DPEHPK3PXP\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plain.Secrets) != 2 || plain.Secrets[1].Name != "GitHub 2FA" {
		t.Errorf("plain row = %+v, want companion %q", plain.Secrets, "GitHub 2FA")
	}
}

func TestCSVImporter_EmptyExport(t *testing.T) {
	if _, err := parseCSV(t, "Title,Url,Username,Password,OTP,Notes\n"); err != importers.ErrEmptyExport {
		t.Fatalf("expected ErrEmptyExport for header-only file, got %v", err)
	}
}

// "no valid secrets found" on its own is unactionable: the per-row reasons must
// reach the caller even though Parse reports ErrEmptyExport.
func TestCSVImporter_EmptyExportKeepsRowWarnings(t *testing.T) {
	res, err := parseCSV(t, "Title,Url,Username,Password,OTP,Notes\nOrphan,,,,,\nOther,,,,,\n")
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("Parse() error = %v, want ErrEmptyExport", err)
	}
	if res == nil || len(res.Warnings) != 2 {
		t.Fatalf("Parse() result = %+v, want one warning per skipped row", res)
	}
	if !strings.Contains(res.Warnings[0], "Orphan") {
		t.Errorf("warning %q does not name the skipped row", res.Warnings[0])
	}
}
