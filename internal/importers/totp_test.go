package importers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompanionTOTPName(t *testing.T) {
	tests := []struct {
		title      string
		hasPrimary bool
		want       string
	}{
		{"GitHub", false, "GitHub 2FA"},
		{"GitHub", true, "GitHub 2FA"},
		// Seed-only row already named for 2FA: keep it.
		{"GitHub 2FA", false, "GitHub 2FA"},
		{"GitHub 2fa", false, "GitHub 2fa"},
		{"2FA", false, "2FA"},
		{"  GitHub  ", false, "GitHub 2FA"},
		// "2FA" must be a whole trailing word, not any suffix match.
		{"Cloudflare2FA", false, "Cloudflare2FA 2FA"},
		{"2FA Codes", false, "2FA Codes 2FA"},
		// A primary secret owns the bare title, so the companion must differ
		// rather than let deduplication rename it to "GitHub 2FA-1".
		{"GitHub 2FA", true, "GitHub 2FA 2FA"},
	}

	for _, tt := range tests {
		if got := CompanionTOTPName(tt.title, tt.hasPrimary); got != tt.want {
			t.Errorf("CompanionTOTPName(%q, %v) = %q, want %q", tt.title, tt.hasPrimary, got, tt.want)
		}
	}
}

func TestExtractTOTP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"clean base32", "JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP", false},
		{"spaces and hyphens", "jbsw y3dp-ehpk 3pxp", "JBSWY3DPEHPK3PXP", false},
		{"otpauth URI", "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", "JBSWY3DPEHPK3PXP", false},
		{"otpauth URI lowercase seed", "otpauth://totp/Test?secret=jbswy3dpehpk3pxp", "JBSWY3DPEHPK3PXP", false},
		{"otpauth URI without secret", "otpauth://totp/Test?issuer=NoSecret", "", true},
		{"invalid base32 alphabet", "JBSWY3DPEHPK3818", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractTOTP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractTOTP(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ExtractTOTP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildCompanionTOTP(t *testing.T) {
	t.Run("valid seed builds companion secret", func(t *testing.T) {
		sec, err := BuildCompanionTOTP("GitHub", "jbsw y3dp ehpk 3pxp", "https://github.com", "notes", []string{"dev"}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sec == nil {
			t.Fatal("expected a companion secret")
		}
		if sec.Name != "GitHub 2FA" || sec.Type != TypeTwoFactor {
			t.Errorf("unexpected identity: name=%q type=%q", sec.Name, sec.Type)
		}
		if sec.URL != "https://github.com" || sec.Notes != "notes" || len(sec.Labels) != 1 {
			t.Errorf("metadata not carried over: %+v", sec)
		}

		var payload map[string]string
		if err := json.Unmarshal(sec.Payload, &payload); err != nil {
			t.Fatalf("payload is not valid JSON: %v", err)
		}
		if payload["securityCode"] != "JBSWY3DPEHPK3PXP" {
			t.Errorf("payload = %v, want normalized seed", payload)
		}
	})

	t.Run("malformed seed reports the owning title", func(t *testing.T) {
		_, err := BuildCompanionTOTP("GitHub", "NOT_BASE32_818", "", "", nil, true)
		if err == nil {
			t.Fatal("expected an error for a malformed seed")
		}
		if !strings.Contains(err.Error(), `invalid 2FA seed for "GitHub"`) {
			t.Errorf("error must name the secret, got %q", err)
		}
	})

	t.Run("absent seed yields no secret", func(t *testing.T) {
		sec, err := BuildCompanionTOTP("GitHub", "   ", "", "", nil, false)
		if err != nil || sec != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", sec, err)
		}
	})
}
