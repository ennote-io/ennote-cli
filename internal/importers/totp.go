package importers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ennote-io/ennote-cli/internal/validation"
)

// ExtractTOTP normalizes a raw TOTP seed or an otpauth:// URI into a validated
// Base32 seed. An empty input yields an empty seed and no error.
func ExtractTOTP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	secret := raw
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("malformed otpauth URI: %w", err)
		}
		secret = u.Query().Get("secret")
		if secret == "" {
			return "", fmt.Errorf("otpauth URI missing 'secret' parameter")
		}
	}

	return validation.ParseBase32(secret)
}

// CompanionTOTPName names the companion secret for baseTitle, appending " 2FA".
// hasPrimary states whether the row also produced a credential or note secret
// under that title; when it did not, a title already ending in "2FA" is kept
// as-is rather than doubled.
func CompanionTOTPName(baseTitle string, hasPrimary bool) string {
	trimmed := strings.TrimSpace(baseTitle)
	if hasPrimary {
		return trimmed + " 2FA"
	}

	lower := strings.ToLower(trimmed)
	if lower == "2fa" || strings.HasSuffix(lower, " 2fa") {
		return trimmed
	}
	return trimmed + " 2FA"
}

// BuildCompanionTOTP returns a TWO_FACTOR secret named by CompanionTOTPName.
// It returns (nil, nil) when rawTOTP is empty, and an error when the seed is
// present but unusable, which callers record as a warning.
func BuildCompanionTOTP(baseTitle, rawTOTP, targetURL, notes string, labels []string, hasPrimary bool) (*ImportedSecret, error) {
	if strings.TrimSpace(rawTOTP) == "" {
		return nil, nil
	}

	seed, err := ExtractTOTP(rawTOTP)
	if err != nil {
		return nil, fmt.Errorf("invalid 2FA seed for %q: %w", baseTitle, err)
	}

	payload, err := json.Marshal(map[string]string{"securityCode": seed})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal 2FA payload for %q: %w", baseTitle, err)
	}

	return &ImportedSecret{
		Name:    CompanionTOTPName(baseTitle, hasPrimary),
		Type:    TypeTwoFactor,
		URL:     targetURL,
		Labels:  labels,
		Notes:   notes,
		Payload: payload,
	}, nil
}
