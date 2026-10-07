package bitwarden

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

func findSecret(secrets []importers.ImportedSecret, name string) (importers.ImportedSecret, bool) {
	for _, s := range secrets {
		if s.Name == name {
			return s, true
		}
	}
	return importers.ImportedSecret{}, false
}

func assertLogin(t *testing.T, s importers.ImportedSecret, login, password string) {
	t.Helper()

	payload := decodeFlatPayload(t, s.Payload)
	if payload["login"] != login || payload["password"] != password {
		t.Errorf("%s payload = %v, want login %q password %q", s.Name, payload, login, password)
	}
}

func TestCSVImporter_MatchHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{
			name:    "valid individual vault export",
			headers: []string{"folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"},
			want:    true,
		},
		{
			name:    "valid organization vault export",
			headers: []string{"collections", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"},
			want:    true,
		},
		{
			name:    "case insensitive and trimmed headers",
			headers: []string{" FOLDER ", "Favorite", "Type", "Name", "Notes", "Fields", "Reprompt", "LOGIN_URI", "Login_Username", "Login_Password", "Login_Totp"},
			want:    true,
		},
		{
			name:    "invalid non-bitwarden - lastpass csv with grouping",
			headers: []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"},
			want:    false,
		},
		{
			name:    "invalid non-bitwarden - 1password csv",
			headers: []string{"title", "url", "username", "password", "otp", "notes"},
			want:    false,
		},
		{
			name:    "invalid non-bitwarden - generic ennote csv",
			headers: []string{"name", "type", "value", "login", "password"},
			want:    false,
		},
		{
			name:    "only password column among login columns",
			headers: []string{"folder", "name", "login_password"},
			want:    true,
		},
		{
			name:    "non-credential bitwarden columns alone do not match",
			headers: []string{"folder", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_totp"},
			want:    false,
		},
		{
			name:    "missing scope column",
			headers: []string{"favorite", "type", "name", "notes", "fields", "login_username", "login_password"},
			want:    false,
		},
		{
			name:    "missing name column",
			headers: []string{"folder", "type", "notes", "fields", "login_username", "login_password"},
			want:    false,
		},
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

func TestCSVImporter_ParseIndividualVault(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Social,1,login,Twitter,My twitter note,,0,twitter.com,me@example.com,password123,JBSWY3DPEHPK3PXP
Finance,,login,My Bank,Bank PIN is 1234,"PIN: 1234",0,https://bank.example.com,john.smith,bankpass,
,,note,My Note,This is a secure note.,,0,,,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 4 {
		t.Fatalf("len(Secrets) = %d, want 4", len(res.Secrets))
	}

	// 1. Twitter Login
	twitter, ok := findSecret(res.Secrets, "Twitter")
	if !ok {
		t.Fatal("Twitter secret not found")
	}
	if twitter.Type != importers.TypeLoginPassword {
		t.Errorf("Twitter type = %s, want %s", twitter.Type, importers.TypeLoginPassword)
	}
	if twitter.URL != "twitter.com" {
		t.Errorf("Twitter URL = %q, want %q", twitter.URL, "twitter.com")
	}
	if twitter.Notes != "My twitter note" {
		t.Errorf("Twitter Notes = %q, want %q", twitter.Notes, "My twitter note")
	}
	if !slices.Contains(twitter.Labels, "Social") || !slices.Contains(twitter.Labels, "favorite") {
		t.Errorf("Twitter Labels = %v, want Social and favorite", twitter.Labels)
	}
	twitterPayload := decodeFlatPayload(t, twitter.Payload)
	if twitterPayload["login"] != "me@example.com" || twitterPayload["password"] != "password123" {
		t.Errorf("Twitter payload = %v, want login/password", twitterPayload)
	}

	// 2. Twitter 2FA Companion
	twitterTOTP, ok := findSecret(res.Secrets, "Twitter 2FA")
	if !ok {
		t.Fatal("Twitter 2FA secret not found")
	}
	if twitterTOTP.Type != importers.TypeTwoFactor {
		t.Errorf("Twitter 2FA type = %s, want %s", twitterTOTP.Type, importers.TypeTwoFactor)
	}
	if twitterTOTP.URL != "twitter.com" {
		t.Errorf("Twitter 2FA URL = %q, want %q", twitterTOTP.URL, "twitter.com")
	}
	if twitterTOTP.Notes != "My twitter note" {
		t.Errorf("Twitter 2FA Notes = %q, want %q", twitterTOTP.Notes, "My twitter note")
	}
	totpPayload := decodeFlatPayload(t, twitterTOTP.Payload)
	if totpPayload["securityCode"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Twitter 2FA payload = %v, want JBSWY3DPEHPK3PXP", totpPayload)
	}

	// 3. My Bank Login (fields merged to notes)
	bank, ok := findSecret(res.Secrets, "My Bank")
	if !ok {
		t.Fatal("My Bank secret not found")
	}
	if bank.Notes != "Bank PIN is 1234\n\nPIN: 1234" {
		t.Errorf("My Bank Notes = %q, want merged notes and fields", bank.Notes)
	}
	if !slices.Contains(bank.Labels, "Finance") || slices.Contains(bank.Labels, "favorite") {
		t.Errorf("My Bank Labels = %v, want Finance and not favorite", bank.Labels)
	}

	// 4. Secure Note
	note, ok := findSecret(res.Secrets, "My Note")
	if !ok {
		t.Fatal("My Note secret not found")
	}
	if note.Type != importers.TypeSecurityNotes {
		t.Errorf("My Note type = %s, want %s", note.Type, importers.TypeSecurityNotes)
	}
	if note.Notes != "" {
		t.Errorf("My Note Notes metadata must be empty, got %q", note.Notes)
	}
	notePayload := decodeFlatPayload(t, note.Payload)
	if notePayload["securityNotes"] != "This is a secure note." {
		t.Errorf("My Note payload = %v, want 'This is a secure note.'", notePayload)
	}
}

func TestCSVImporter_ParseOrganizationVault(t *testing.T) {
	csv := `collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
"Social,Marketing",login,Twitter,,,0,twitter.com,me@example.com,password123,
Finance,login,EVGA,,,0,https://www.evga.com/support/login.asp,hello@bitwarden.com,fakepassword,
Parent Collection,,,,,,,,,,
Parent Collection/Child Collection,login,Shared API,,,,https://api.example.com,svc_acct,secret,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 3 {
		t.Fatalf("len(Secrets) = %d, want 3", len(res.Secrets))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(res.Warnings), res.Warnings)
	}

	twitter, ok := findSecret(res.Secrets, "Twitter")
	if !ok {
		t.Fatal("Twitter secret not found")
	}
	if !slices.Contains(twitter.Labels, "Social") || !slices.Contains(twitter.Labels, "Marketing") {
		t.Errorf("Twitter Labels = %v, want Social and Marketing", twitter.Labels)
	}

	shared, ok := findSecret(res.Secrets, "Shared API")
	if !ok {
		t.Fatal("Shared API secret not found")
	}
	if !slices.Contains(shared.Labels, "Parent Collection/Child Collection") {
		t.Errorf("Shared API Labels = %v, want Parent Collection/Child Collection", shared.Labels)
	}
}

func TestCSVImporter_VaultFiltering(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Dev,1,login,Dev DB,,,0,,devuser,devpw,
Dev/Cloud,,login,AWS,,,0,,awsuser,awspw,
Development,,login,Other DB,,,0,,otheruser,otherpw,
,,login,No Folder Secret,,,0,,nouser,nopw,
`

	// 1. Filter "Dev" should match "Dev" and "Dev/Cloud", but not "Development" or unassigned
	res, err := parseCSV(t, csv, importers.ImportOptions{VaultFilter: "Dev"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("len(Secrets) = %d, want 2", len(res.Secrets))
	}
	if _, ok := findSecret(res.Secrets, "Dev DB"); !ok {
		t.Error("Dev DB should be included")
	}
	if _, ok := findSecret(res.Secrets, "AWS"); !ok {
		t.Error("AWS (Dev/Cloud) should be included")
	}
	if _, ok := findSecret(res.Secrets, "Other DB"); ok {
		t.Error("Other DB (Development) should NOT be included")
	}
	if _, ok := findSecret(res.Secrets, "No Folder Secret"); ok {
		t.Error("No Folder Secret should NOT be included when filter is set")
	}

	// 2. Empty filter should match all rows
	allRes, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(allRes.Secrets) != 4 {
		t.Fatalf("len(allRes.Secrets) = %d, want 4", len(allRes.Secrets))
	}
}

func TestCSVImporter_OrgVaultMultiCollectionFiltering(t *testing.T) {
	csv := `collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
"Social,Marketing",login,Twitter,,,0,,user,pw,
"Engineering,Infra/Prod",login,Prod Server,,,0,,user,pw,
Finance,login,Banking,,,0,,user,pw,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{VaultFilter: "Marketing"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(res.Secrets))
	}
	if res.Secrets[0].Name != "Twitter" {
		t.Errorf("Secret name = %q, want Twitter", res.Secrets[0].Name)
	}
}

func TestCSVImporter_ContentGateAndTOTPOnly(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,TOTP Only 2FA,,,,,,,JBSWY3DPEHPK3PXP
,,login,Empty Login,,,,,,,
,,note,Empty Note,,,,,,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only TOTP Only 2FA should produce a secret (standalone TWO_FACTOR, keeping row name without doubling 2FA)
	if len(res.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(res.Secrets))
	}
	totpSecret := res.Secrets[0]
	if totpSecret.Name != "TOTP Only 2FA" {
		t.Errorf("Secret name = %q, want 'TOTP Only 2FA'", totpSecret.Name)
	}
	if totpSecret.Type != importers.TypeTwoFactor {
		t.Errorf("Secret type = %s, want %s", totpSecret.Type, importers.TypeTwoFactor)
	}

	// Empty Login and Empty Note should produce warnings
	if len(res.Warnings) != 2 {
		t.Fatalf("len(Warnings) = %d, want 2 (got %v)", len(res.Warnings), res.Warnings)
	}
	if !strings.Contains(res.Warnings[0], "Empty Login") {
		t.Errorf("Warning 0 missing 'Empty Login': %s", res.Warnings[0])
	}
	if !strings.Contains(res.Warnings[1], "Empty Note") {
		t.Errorf("Warning 1 missing 'Empty Note': %s", res.Warnings[1])
	}
}

func TestCSVImporter_BlankAndUnknownTypeInference(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,, ,Inferred Credential,,,,,inferred_user,inferred_pw,
,, ,Inferred Note,Note content,,,,,,
,,MYSTERY_TYPE,Unknown Type,,,,,unk_user,unk_pw,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 3 {
		t.Fatalf("len(Secrets) = %d, want 3", len(res.Secrets))
	}

	inferredCred, _ := findSecret(res.Secrets, "Inferred Credential")
	if inferredCred.Type != importers.TypeLoginPassword {
		t.Errorf("Inferred Credential type = %s, want %s", inferredCred.Type, importers.TypeLoginPassword)
	}
	assertLogin(t, inferredCred, "inferred_user", "inferred_pw")

	inferredNote, _ := findSecret(res.Secrets, "Inferred Note")
	if inferredNote.Type != importers.TypeSecurityNotes {
		t.Errorf("Inferred Note type = %s, want %s", inferredNote.Type, importers.TypeSecurityNotes)
	}

	unkType, _ := findSecret(res.Secrets, "Unknown Type")
	if unkType.Type != importers.TypeLoginPassword {
		t.Errorf("Unknown Type type = %s, want %s", unkType.Type, importers.TypeLoginPassword)
	}
	assertLogin(t, unkType, "unk_user", "unk_pw")

	// One warning for unknown type
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "unknown type \"MYSTERY_TYPE\"") {
		t.Errorf("expected 1 unknown type warning, got: %v", res.Warnings)
	}
}

func TestCSVImporter_FieldsRoutingAndSecurityNotesIsolation(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,Login With Fields,Login note,"API_KEY: secret123",0,,user,pw,JBSWY3DPEHPK3PXP
,,login,Fields Only No Note,,"CUSTOM: val",0,,user,pw,
,,note,Note With Fields,Body text,"Extra: detail",0,,,,JBSWY3DPEHPK3PXP
,,note,Note Fields Only,,"Solo field",0,,,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Login with fields
	login1, _ := findSecret(res.Secrets, "Login With Fields")
	if login1.Notes != "Login note\n\nAPI_KEY: secret123" {
		t.Errorf("Login Notes = %q, want joined notes and fields", login1.Notes)
	}
	login1TOTP, _ := findSecret(res.Secrets, "Login With Fields 2FA")
	if login1TOTP.Notes != "Login note\n\nAPI_KEY: secret123" {
		t.Errorf("Login 2FA Notes = %q, want joined notes and fields", login1TOTP.Notes)
	}

	// 2. Login with fields only (no leading separator)
	login2, _ := findSecret(res.Secrets, "Fields Only No Note")
	if login2.Notes != "CUSTOM: val" {
		t.Errorf("Login2 Notes = %q, want 'CUSTOM: val'", login2.Notes)
	}

	// 3. Note with fields (payload holds merged body, ImportedSecret.Notes is empty)
	note1, _ := findSecret(res.Secrets, "Note With Fields")
	if note1.Notes != "" {
		t.Errorf("SECURITY_NOTES Notes metadata must be empty, got %q", note1.Notes)
	}
	note1Payload := decodeFlatPayload(t, note1.Payload)
	if note1Payload["securityNotes"] != "Body text\n\nExtra: detail" {
		t.Errorf("note1 payload = %v, want 'Body text\\n\\nExtra: detail'", note1Payload)
	}
	note1TOTP, _ := findSecret(res.Secrets, "Note With Fields 2FA")
	if note1TOTP.Notes != "" {
		t.Errorf("SECURITY_NOTES companion 2FA Notes metadata must be empty, got %q", note1TOTP.Notes)
	}

	// 4. Note with fields only
	note2, _ := findSecret(res.Secrets, "Note Fields Only")
	if note2.Notes != "" {
		t.Errorf("SECURITY_NOTES Notes metadata must be empty, got %q", note2.Notes)
	}
	note2Payload := decodeFlatPayload(t, note2.Payload)
	if note2Payload["securityNotes"] != "Solo field" {
		t.Errorf("note2 payload = %v, want 'Solo field'", note2Payload)
	}
}

func TestCSVImporter_NoteWithCredentialsRejected(t *testing.T) {
	// A declared type=note row with credentials but no note body should NOT be silently re-typed
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,note,Miscalibrated Note,,,,,admin,secretpass,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if len(res.Secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(res.Secrets))
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "Miscalibrated Note") {
		t.Errorf("expected warning naming Miscalibrated Note, got: %v", res.Warnings)
	}
}

func TestCSVImporter_URINormalization(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,Multi URI,,,0,"https://first.example.com,https://second.example.com",user,pw,JBSWY3DPEHPK3PXP
,,login,First Invalid,,,0,"invalid_uri,https://valid.example.com",user,pw,
,,login,All Invalid,,,0,androidapp://com.example,user,pw,
,,login,Bare Host,,,0,twitter.com,user,pw,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	multi, _ := findSecret(res.Secrets, "Multi URI")
	if multi.URL != "https://first.example.com" {
		t.Errorf("Multi URI URL = %q, want first valid segment", multi.URL)
	}
	multiTOTP, _ := findSecret(res.Secrets, "Multi URI 2FA")
	if multiTOTP.URL != "https://first.example.com" {
		t.Errorf("Multi URI 2FA URL = %q, want first valid segment", multiTOTP.URL)
	}

	firstInv, _ := findSecret(res.Secrets, "First Invalid")
	if firstInv.URL != "https://valid.example.com" {
		t.Errorf("First Invalid URL = %q, want valid segment", firstInv.URL)
	}

	allInv, _ := findSecret(res.Secrets, "All Invalid")
	if allInv.URL != "" {
		t.Errorf("All Invalid URL = %q, want empty string", allInv.URL)
	}

	bare, _ := findSecret(res.Secrets, "Bare Host")
	if bare.URL != "twitter.com" {
		t.Errorf("Bare Host URL = %q, want twitter.com", bare.URL)
	}
}

func TestCSVImporter_SteamTOTPRejected(t *testing.T) {
	// Valid Base32 seed prefixed with steam://
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,Steam Game Account,,,0,https://store.steampowered.com,gamer,pass,steam://JBSWY3DPEHPK3PXP
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Login must import successfully
	if len(res.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(res.Secrets))
	}
	if res.Secrets[0].Name != "Steam Game Account" {
		t.Errorf("Secret name = %q, want 'Steam Game Account'", res.Secrets[0].Name)
	}

	// Companion 2FA must NOT be produced
	if _, ok := findSecret(res.Secrets, "Steam Game Account 2FA"); ok {
		t.Error("Steam 2FA companion should NOT be created")
	}

	// Warning must be recorded for invalid 2FA seed
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "invalid 2FA seed") {
		t.Errorf("expected 1 invalid 2FA seed warning, got: %v", res.Warnings)
	}
}

func TestCSVImporter_CollectionPlaceholdersAndRaggedRecords(t *testing.T) {
	// Parent Collection has extra trailing commas (ragged record)
	csv := `collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Parent Collection,,,,,,,,,,,
Parent Collection/Child Collection,,,,,,,,,,
Parent Collection/Child Collection,login,Actual Item,,,0,https://example.com,user,pw,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(res.Secrets))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(res.Warnings), res.Warnings)
	}
	if res.Secrets[0].Name != "Actual Item" {
		t.Errorf("Secret name = %q, want 'Actual Item'", res.Secrets[0].Name)
	}
}

func TestCSVImporter_EmptyExportReturnsWarnings(t *testing.T) {
	csv := `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,,login,Bad Row 1,,,,,,
,,note,Bad Row 2,,,,,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if res == nil {
		t.Fatal("result must not be nil when returning ErrEmptyExport")
	}
	if len(res.Warnings) != 2 {
		t.Errorf("len(Warnings) = %d, want 2", len(res.Warnings))
	}
}

func TestCSVImporter_OnlyPlaceholdersReturnsEmptyWithoutWarnings(t *testing.T) {
	csv := `collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Parent Collection,,,,,,,,,,
Child Collection,,,,,,,,,,
`

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if res == nil {
		t.Fatal("result must not be nil")
	}
	if len(res.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d: %v", len(res.Warnings), res.Warnings)
	}
}

func TestCSVImporter_BOMAndWhitespace(t *testing.T) {
	bomCSV := "\xEF\xBB\xBFfolder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		"  Work  , 1 , login ,  My App  , , , 0 , https://app.example.com , appuser , secret , \n"

	res, err := parseCSV(t, bomCSV, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Secrets) != 1 {
		t.Fatalf("len(Secrets) = %d, want 1", len(res.Secrets))
	}
	s := res.Secrets[0]
	if s.Name != "My App" {
		t.Errorf("Name = %q, want 'My App'", s.Name)
	}
	if !slices.Contains(s.Labels, "Work") || !slices.Contains(s.Labels, "favorite") {
		t.Errorf("Labels = %v, want Work and favorite", s.Labels)
	}
}

const individualHeader = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"

func TestCSVImporter_OtpauthURISeed(t *testing.T) {
	csv := individualHeader +
		",,login,Uri Seed,,,0,,user,pw,otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %v", res.Warnings)
	}

	totp, ok := findSecret(res.Secrets, "Uri Seed 2FA")
	if !ok {
		t.Fatal("Uri Seed 2FA secret not found")
	}
	if got := decodeFlatPayload(t, totp.Payload)["securityCode"]; got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("securityCode = %q, want JBSWY3DPEHPK3PXP", got)
	}
}

func TestCSVImporter_InvalidSeedKeepsPrimary(t *testing.T) {
	csv := individualHeader +
		",,login,Bad Seed,,,0,,user,pw,not*base32!\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "Bad Seed" {
		t.Fatalf("Secrets = %+v, want only the login", res.Secrets)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "invalid 2FA seed") {
		t.Errorf("expected 1 invalid 2FA seed warning, got: %v", res.Warnings)
	}
}

func TestCSVImporter_InvalidSeedOnlyRowWarnsOnce(t *testing.T) {
	csv := individualHeader +
		",,login,Seed Only,,,0,,,,not*base32!\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "invalid 2FA seed") {
		t.Errorf("expected exactly the invalid seed warning, got: %v", res.Warnings)
	}
}

func TestCSVImporter_LoginWithoutCredentialsFallsBackToNote(t *testing.T) {
	csv := individualHeader +
		",,login,Notes Only Login,Remember this,,0,,,,JBSWY3DPEHPK3PXP\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("len(Secrets) = %d, want 2", len(res.Secrets))
	}

	note, _ := findSecret(res.Secrets, "Notes Only Login")
	if note.Type != importers.TypeSecurityNotes || note.Notes != "" {
		t.Errorf("primary = type %s notes %q, want SECURITY_NOTES with empty Notes", note.Type, note.Notes)
	}
	if got := decodeFlatPayload(t, note.Payload)["securityNotes"]; got != "Remember this" {
		t.Errorf("securityNotes = %q, want 'Remember this'", got)
	}
	if _, ok := findSecret(res.Secrets, "Notes Only Login 2FA"); !ok {
		t.Error("companion 2FA should be created beside the note")
	}
}

func TestCSVImporter_UnknownTypeWithoutContentWarnsOnce(t *testing.T) {
	csv := individualHeader +
		",,card,My Card,,,0,,,,\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "My Card") {
		t.Errorf("expected exactly one warning naming My Card, got: %v", res.Warnings)
	}
}

func TestCSVImporter_NamedCollectionRowIsNotPlaceholder(t *testing.T) {
	csv := "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		"Finance,,Named Only,,,,,,,\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "Named Only") {
		t.Errorf("a row carrying a name must be reported, not skipped silently; got: %v", res.Warnings)
	}
}

func TestCSVImporter_PlaceholderFilteredByVault(t *testing.T) {
	csv := "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
		"Parent,,,,,,,,,\n" +
		"Parent/Child,login,Item,,,0,,user,pw,\n"

	res, err := parseCSV(t, csv, importers.ImportOptions{VaultFilter: "Parent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Secrets) != 1 || len(res.Warnings) != 0 {
		t.Errorf("Secrets = %d, Warnings = %v; want 1 secret and no warnings", len(res.Secrets), res.Warnings)
	}
}

func TestCSVImporter_EmptyInput(t *testing.T) {
	for name, content := range map[string]string{
		"empty file":      "",
		"whitespace only": " \n\n",
		"header only":     individualHeader,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCSV(t, content, importers.ImportOptions{}); !errors.Is(err, importers.ErrEmptyExport) {
				t.Fatalf("expected ErrEmptyExport, got %v", err)
			}
		})
	}
}
