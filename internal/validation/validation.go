package validation

import (
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
)

var (
	// URLRegex matches valid HTTP, HTTPS, or host:port URLs.
	URLRegex = regexp.MustCompile(`(?i)^(https?://)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|((\d{1,3}\.){3}\d{1,3}))(:\d+)?(/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(#[-a-z\d_]*)?$`)

	// IPv4Regex matches standard IPv4 addresses.
	IPv4Regex = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]?)(\.|-)){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]?)$`)

	// IPv6Regex matches standard IPv6 addresses.
	IPv6Regex = regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`)
)

// IsValidEndpoint returns true if val matches a valid URL, IPv4, or IPv6 pattern.
func IsValidEndpoint(val string) bool {
	if val == "" {
		return false
	}
	return URLRegex.MatchString(val) || IPv4Regex.MatchString(val) || IPv6Regex.MatchString(val)
}

// ValidateEndpoint returns an error if the value is not a valid endpoint (URL, IPv4, or IPv6 address).
func ValidateEndpoint(value string) error {
	if IsValidEndpoint(value) {
		return nil
	}
	return fmt.Errorf("please enter a valid URL, IPv4, or IPv6 address")
}

// NormalizeBase32 cleans whitespace and dashes from a base32 string and converts to uppercase.
func NormalizeBase32(secret string) string {
	cleanSecret := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	return strings.ReplaceAll(cleanSecret, "-", "")
}

// ValidateBase32 returns an error if the secret cannot be decoded as Base32 or is empty.
func ValidateBase32(secret string) error {
	if secret == "" {
		return fmt.Errorf("secret key cannot be empty")
	}

	paddedSecret := secret
	if padLen := len(secret) % 8; padLen != 0 {
		paddedSecret += strings.Repeat("=", 8-padLen)
	}

	if _, err := base32.StdEncoding.DecodeString(paddedSecret); err != nil {
		return fmt.Errorf("invalid Base32 secret key format")
	}

	return nil
}

// ParseBase32 normalizes and validates a Base32 string, returning the normalized key.
func ParseBase32(secret string) (string, error) {
	cleanSecret := NormalizeBase32(secret)
	if err := ValidateBase32(cleanSecret); err != nil {
		return "", err
	}
	return cleanSecret, nil
}
