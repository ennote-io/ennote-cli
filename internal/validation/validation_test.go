package validation

import (
	"testing"
)

func TestIsValidEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty string", "", false},
		{"valid http URL", "http://example.com", true},
		{"valid https URL", "https://app.ennote.io/secrets?id=123#anchor", true},
		{"valid URL with port", "https://example.com:8080/api/v1", true},
		{"valid domain without scheme", "login.example.com", true},
		{"valid domain with port and path", "db.prod.internal:5432/main", true},
		{"valid IPv4", "192.168.1.1", true},
		{"valid IPv4 with port", "10.0.0.5:5432", true},
		{"valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"valid IPv6 shorthand", "::1", true},
		{"invalid random string", "not a valid url or ip @@", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidEndpoint(tt.input)
			if got != tt.want {
				t.Errorf("IsValidEndpoint(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	if err := ValidateEndpoint("https://ennote.io"); err != nil {
		t.Errorf("expected nil error for valid URL, got %v", err)
	}
	if err := ValidateEndpoint("invalid string @@"); err == nil {
		t.Errorf("expected error for invalid endpoint, got nil")
	}
}

func TestNormalizeBase32(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"uppercase and clean", "JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"},
		{"lowercase with spaces and dashes", "jbsw-y3dp ehpk-3pxp", "JBSWY3DPEHPK3PXP"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeBase32(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeBase32(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateBase32(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid secret", "JBSWY3DPEHPK3PXP", false},
		{"valid unpadded secret", "MZXW6YTBOI", false},
		{"empty string", "", true},
		{"invalid characters", "JBSWY3DPEHPK89!@", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBase32(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBase32(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseBase32(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid clean secret",
			input:   "JBSWY3DPEHPK3PXP",
			want:    "JBSWY3DPEHPK3PXP",
			wantErr: false,
		},
		{
			name:    "valid secret with spaces and dashes",
			input:   "jbsw-y3dp ehpk-3pxp",
			want:    "JBSWY3DPEHPK3PXP",
			wantErr: false,
		},
		{
			name:    "valid unpadded secret",
			input:   "MZXW6YTBOI",
			want:    "MZXW6YTBOI",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			input:   "JBSWY3DPEHPK89!@",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBase32(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseBase32(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseBase32(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
