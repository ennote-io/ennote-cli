package kvtext

import (
	"reflect"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "comments, quotes and export prefix",
			raw:  "# stripe\nSTRIPE_KEY=\"sk_live_123\"\nexport DB_PASS='p@ss=word'\n\nEMPTY=\n",
			want: map[string]string{"STRIPE_KEY": "sk_live_123", "DB_PASS": "p@ss=word", "EMPTY": ""},
		},
		{
			name: "colon in a value belongs to the value",
			raw:  "URL=https://example.com:8443\n",
			want: map[string]string{"URL": "https://example.com:8443"},
		},
		{
			name: "prose lines are dropped",
			raw:  "KEY=value\nthis is prose with no pair\nOTHER=2\n",
			want: map[string]string{"KEY": "value", "OTHER": "2"},
		},
		{
			name: "repeated key keeps the last value",
			raw:  "KEY=first\nKEY=second\n",
			want: map[string]string{"KEY": "second"},
		},
		// The documented input is a .env file. Anything else must yield no
		// pairs so `secret create` reports it instead of reinterpreting the
		// payload as some other format.
		{
			name: "yaml is not dotenv",
			raw:  "host: localhost\nport: 5432\n",
			want: map[string]string{},
		},
		{
			name: "json is not dotenv",
			raw:  `{"host":"db.local","port":5432}`,
			want: map[string]string{},
		},
		{
			name: "colon text with an equals sign is not dotenv",
			raw:  "note: a=b\n",
			want: map[string]string{},
		},
		{
			name: "empty input",
			raw:  "   \n\t\n",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseDotenv(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseDotenv() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "empty input",
			raw:  "   \n\t\n",
			want: map[string]string{},
		},
		{
			name: "dotenv with comments, quotes and export prefix",
			raw:  "# stripe\nSTRIPE_KEY=\"sk_live_123\"\nexport DB_PASS='p@ss=word'\n\nEMPTY=\n",
			want: map[string]string{"STRIPE_KEY": "sk_live_123", "DB_PASS": "p@ss=word", "EMPTY": ""},
		},
		{
			name: "json object with mixed scalars",
			raw:  `{"key":"value","port":5432,"debug":true,"missing":null}`,
			want: map[string]string{"key": "value", "port": "5432", "debug": "true", "missing": ""},
		},
		{
			name: "json nested value is compact json string",
			raw:  `{"db":{"host":"localhost","port":5432},"hosts":["a","b"]}`,
			want: map[string]string{"db": `{"host":"localhost","port":5432}`, "hosts": `["a","b"]`},
		},
		{
			name: "flat colon text",
			raw:  "host: localhost\nport: 5432\nenabled: true\n",
			want: map[string]string{"host": "localhost", "port": "5432", "enabled": "true"},
		},
		{
			name: "colon delimited value containing both delimiters",
			raw:  "Network Name: CorpNet\nPassword: p@ss=word\n",
			want: map[string]string{"Network Name": "CorpNet", "Password": "p@ss=word"},
		},
		// Values are stored byte-for-byte: a YAML parser would resolve these
		// scalars and silently rewrite the secret.
		{
			name: "numeric-looking values are not coerced",
			raw:  "pin: 011\nmode: 0644\nver: 1.20\npw: 2e3\n",
			want: map[string]string{"pin": "011", "mode": "0644", "ver": "1.20", "pw": "2e3"},
		},
		{
			name: "keys with spaces preserved verbatim",
			raw:  "home address: 123 Main St\n",
			want: map[string]string{"home address": "123 Main St"},
		},
		{
			name: "prose lines before any pair are dropped",
			raw:  "this is prose with no pair\nKEY=value\n",
			want: map[string]string{"KEY": "value"},
		},
		{
			name: "continuation lines fold into preceding key",
			raw:  "Description: line one\nline two\nOtherKey: val\n",
			want: map[string]string{"Description": "line one\nline two", "OtherKey": "val"},
		},
		{
			name: "a notes key claims no special power in Parse",
			raw:  "notes: read me\nhost: h1\nport: 22\n",
			want: map[string]string{"notes": "read me", "host": "h1", "port": "22"},
		},
		{
			name: "comment lines are dropped, not folded into the previous value",
			raw:  "KEY=v\n# a comment\nOTHER=2\n",
			want: map[string]string{"KEY": "v", "OTHER": "2"},
		},
		{
			name: "duplicate keys keep the first value",
			raw:  "KEY=first\nKEY=second\n",
			want: map[string]string{"KEY": "first"},
		},
		{
			name: "dotenv wins over colon parsing when both delimiters appear",
			raw:  "URL=https://example.com:8443\n",
			want: map[string]string{"URL": "https://example.com:8443"},
		},
		{
			name: "unparseable text yields no pairs",
			raw:  "just some prose\nwithout any pairs\n",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseWithTerminalKey(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		terminalKey string
		want        map[string]string
	}{
		{
			name:        "terminal key absorbs colon-bearing lines that follow",
			raw:         "NoteType: Server\nNotes: call ops first\nSee runbook: https://wiki.example/db\nthen escalate\n",
			terminalKey: "notes",
			want:        map[string]string{"NoteType": "Server", "Notes": "call ops first\nSee runbook: https://wiki.example/db\nthen escalate"},
		},
		{
			name:        "terminal key match is case-insensitive",
			raw:         "Host: h1\nNOTES: body\nkey: not a key\n",
			terminalKey: "notes",
			want:        map[string]string{"Host": "h1", "NOTES": "body\nkey: not a key"},
		},
		{
			name:        "blank lines inside the terminal block are preserved",
			raw:         "Host: h1\nNotes: para one\n\npara two\n",
			terminalKey: "notes",
			want:        map[string]string{"Host": "h1", "Notes": "para one\n\npara two"},
		},
		{
			name:        "keys before the terminal key parse normally",
			raw:         "NoteType: Database\nHostname: db1\nPort: 5432\nNotes: rotate quarterly\n",
			terminalKey: "notes",
			want:        map[string]string{"NoteType": "Database", "Hostname": "db1", "Port": "5432", "Notes": "rotate quarterly"},
		},
		{
			name:        "an empty terminal key disables the rule",
			raw:         "Notes: read me\nhost: h1\n",
			terminalKey: "",
			want:        map[string]string{"Notes": "read me", "host": "h1"},
		},
		{
			name:        "a terminal key that never appears changes nothing",
			raw:         "Host: h1\nPort: 22\n",
			terminalKey: "notes",
			want:        map[string]string{"Host": "h1", "Port": "22"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseWithTerminalKey(tt.raw, tt.terminalKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWithTerminalKey(_, %q) = %#v, want %#v", tt.terminalKey, got, tt.want)
			}
		})
	}
}
