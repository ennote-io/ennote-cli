package registry

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

// fakeProvider stands in for a provider-specific importer so precedence is
// testable independently of which providers happen to be registered.
type fakeProvider struct {
	name     string
	required string
}

func (p *fakeProvider) ProviderName() string { return p.name }

func (p *fakeProvider) SupportsVaultFilter() bool { return false }

func (p *fakeProvider) MatchHeaders(headers []string) bool {
	for _, h := range headers {
		if h == p.required {
			return true
		}
	}
	return false
}

func (p *fakeProvider) Parse(io.ReaderAt, int64, importers.ImportOptions) (*importers.ImportResult, error) {
	return &importers.ImportResult{}, nil
}

func puxJSON() []byte {
	return []byte(`{"accounts":[{"attrs":{"name":"Personal","uuid":"a1"},"vaults":[{"attrs":{"name":"Personal","uuid":"v1"},"items":[{"uuid":"i1","categoryUuid":"003","overview":{"title":"Note"},"details":{"notesPlain":"hello"}}]}]}]}`)
}

func puxZip(t *testing.T) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	attrs, err := zw.Create("export.attributes")
	if err != nil {
		t.Fatalf("failed to create zip member: %v", err)
	}
	if _, err := attrs.Write([]byte(`{"version":3}`)); err != nil {
		t.Fatalf("failed to write zip member: %v", err)
	}

	data, err := zw.Create("export.data")
	if err != nil {
		t.Fatalf("failed to create zip member: %v", err)
	}
	if _, err := data.Write(puxJSON()); err != nil {
		t.Fatalf("failed to write zip member: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}
	return buf.Bytes()
}

func TestMatchProviderPrefersStrictOverFallback(t *testing.T) {
	strict := &fakeProvider{name: "Strict CSV", required: "title"}
	// The fallback claims everything, exactly like the native Ennote parser.
	fallback := &fakeProvider{name: "Fallback CSV", required: "title"}

	got := matchProvider([]string{"title", "password"}, []importers.Provider{strict}, fallback)
	if got != importers.Provider(strict) {
		t.Fatalf("resolved %v, want the strict provider to outrank the fallback", got)
	}
}

func TestMatchProviderFallsBackWhenStrictDeclines(t *testing.T) {
	strict := &fakeProvider{name: "Strict CSV", required: "grouping"}
	fallback := &fakeProvider{name: "Fallback CSV", required: "name"}

	got := matchProvider([]string{"name", "value"}, []importers.Provider{strict}, fallback)
	if got != importers.Provider(fallback) {
		t.Fatalf("resolved %v, want the fallback", got)
	}
}

func TestMatchProviderNoMatch(t *testing.T) {
	fallback := &fakeProvider{name: "Fallback CSV", required: "name"}

	if got := matchProvider([]string{"id", "blob"}, nil, fallback); got != nil {
		t.Fatalf("resolved %v, want nil", got)
	}
}

func TestGetImporter(t *testing.T) {
	zipData := puxZip(t)

	tests := []struct {
		name     string
		format   importers.Format
		filename string
		data     []byte
		want     string
		wantErr  error
	}{
		{
			name:     "explicit 1pux format",
			format:   importers.Format1PUX,
			filename: "export.data",
			data:     puxJSON(),
			want:     "1Password 1PUX",
		},
		{
			name:     "auto-detect by 1pux extension",
			format:   importers.FormatAuto,
			filename: "vault.1PUX",
			data:     puxJSON(),
			want:     "1Password 1PUX",
		},
		{
			name:     "auto-detect zip archive members",
			format:   importers.FormatAuto,
			filename: "export.zip",
			data:     zipData,
			want:     "1Password 1PUX",
		},
		{
			name:     "auto-detect raw 1pux json by accounts key",
			format:   importers.FormatAuto,
			filename: "export.data",
			data:     puxJSON(),
			want:     "1Password 1PUX",
		},
		{
			name:     "auto-detect generic csv",
			format:   importers.FormatAuto,
			filename: "secrets.csv",
			data:     []byte("Name,Type,Value\nToken,SECURITY_NOTES,abc\n"),
			want:     "Ennote CSV",
		},
		{
			name:     "explicit csv format on an unrecognized extension",
			format:   importers.FormatCSV,
			filename: "export.data",
			data:     []byte("name,login,password\nAWS,admin,pw\n"),
			want:     "Ennote CSV",
		},
		{
			name:     "csv with a BOM still resolves",
			format:   importers.FormatAuto,
			filename: "excel.csv",
			data:     append([]byte{0xEF, 0xBB, 0xBF}, []byte("Name,Value\nToken,abc\n")...),
			want:     "Ennote CSV",
		},
		{
			// Comma is the only delimiter: an Excel-EU re-save collapses to one
			// column and no provider can claim it.
			name:     "semicolon-delimited export is not claimed",
			format:   importers.FormatCSV,
			filename: "excel-eu.csv",
			data:     []byte("Title;Url;Username;Password;OTPAuth\nSemi;https://semi.example;me;pw;\n"),
			wantErr:  importers.ErrUnknownCSVFormat,
		},
		{
			name:     "header the fallback would also claim resolves to the strict provider",
			format:   importers.FormatAuto,
			filename: "ambiguous.csv",
			data:     []byte("Title,Url,Username,Password,Notes,Value,Type\nRow,https://a.example,me,pw,n,v,LOGIN_PASSWORD\n"),
			want:     "1Password CSV",
		},
		{
			name:     "auto-detect lastpass csv",
			format:   importers.FormatAuto,
			filename: "lastpass.csv",
			data:     []byte("url,username,password,totp,extra,name,grouping,fav\nhttps://example.com,user,pw,,note,Service,Work,0\n"),
			want:     "LastPass CSV",
		},
		{
			name:     "auto-detect bitwarden individual csv",
			format:   importers.FormatAuto,
			filename: "bitwarden_export.csv",
			data:     []byte("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nSocial,1,login,Twitter,,,0,twitter.com,user,pw,\n"),
			want:     "Bitwarden CSV",
		},
		{
			name:     "auto-detect bitwarden org csv",
			format:   importers.FormatAuto,
			filename: "bitwarden_export_org.csv",
			data:     []byte("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nFinance,login,Bank,,,0,bank.com,user,pw,\n"),
			want:     "Bitwarden CSV",
		},
		{
			name:     "unclaimable headers",
			format:   importers.FormatCSV,
			filename: "mystery.csv",
			data:     []byte("id,blob,created_at\n1,x,y\n"),
			wantErr:  importers.ErrUnknownCSVFormat,
		},
		{
			name:     "auto-detect on unclaimable content",
			format:   importers.FormatAuto,
			filename: "mystery.bin",
			data:     []byte("id,blob,created_at\n1,x,y\n"),
			wantErr:  importers.ErrUnsupportedFormat,
		},
		{
			name:     "empty file",
			format:   importers.FormatAuto,
			filename: "empty.csv",
			data:     nil,
			wantErr:  importers.ErrEmptyExport,
		},
		{
			name:     "unsupported format name",
			format:   importers.Format("lastpass"),
			filename: "export.csv",
			data:     []byte("name\nx\n"),
			wantErr:  importers.ErrUnsupportedFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)

			importer, err := GetImporter(tt.format, r, int64(len(tt.data)), tt.filename)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := importer.ProviderName(); got != tt.want {
				t.Errorf("ProviderName() = %q, want %q (%T)", got, tt.want, importer)
			}
		})
	}
}

func TestSniffCSVProviderReportsHeaders(t *testing.T) {
	data := "id,blob\n"
	r := strings.NewReader(data)

	_, err := SniffCSVProvider(r, int64(r.Len()))
	if !errors.Is(err, importers.ErrUnknownCSVFormat) {
		t.Fatalf("error = %v, want ErrUnknownCSVFormat", err)
	}
	if msg := fmt.Sprint(err); !strings.Contains(msg, "id") || !strings.Contains(msg, "blob") {
		t.Errorf("error %q should name the offending headers", msg)
	}
}

func TestRegisteredFallbackIsSeparateFromStrictList(t *testing.T) {
	// Guards the precedence contract: the fallback must never be reachable as a
	// strict provider, or ordering inside one slice would decide precedence.
	for _, provider := range strictCSVProviders {
		if provider == csvFallbackProvider {
			t.Fatalf("fallback provider %q must not appear in strictCSVProviders", provider.ProviderName())
		}
	}
}

// TestStrictProvidersClaimOnlyTheirOwnHeaders guards the disjointness the
// first-match-wins precedence relies on: every vendor's canonical headers must
// be claimed by exactly one strict provider.
func TestStrictProvidersClaimOnlyTheirOwnHeaders(t *testing.T) {
	headerSets := []struct {
		name    string
		want    string
		headers []string
	}{
		{"1password legacy", "1Password CSV", []string{"title", "url", "username", "password", "notes", "otp"}},
		{"1password 8", "1Password CSV", []string{"Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes"}},
		{"lastpass", "LastPass CSV", []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"}},
		{"bitwarden individual", "Bitwarden CSV", []string{"folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"}},
		{"bitwarden organization", "Bitwarden CSV", []string{"collections", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"}},
		{"ennote generic", "", []string{"Name", "Type", "Value", "Login", "Password", "URL", "Labels", "Notes"}},
	}

	for _, hs := range headerSets {
		t.Run(hs.name, func(t *testing.T) {
			var matched []string
			for _, provider := range strictCSVProviders {
				if provider.MatchHeaders(hs.headers) {
					matched = append(matched, provider.ProviderName())
				}
			}

			switch {
			case hs.want == "" && len(matched) != 0:
				t.Errorf("strict providers %v claimed a generic Ennote header; it must reach the fallback", matched)
			case hs.want != "" && (len(matched) != 1 || matched[0] != hs.want):
				t.Errorf("strict providers matching = %v, want exactly [%s]", matched, hs.want)
			}
		})
	}
}
