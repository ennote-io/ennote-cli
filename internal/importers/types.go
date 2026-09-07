package importers

import (
	"errors"
	"io"
)

// SecretType represents the supported Ennote secret types.
type SecretType string

const (
	TypeLoginPassword SecretType = "LOGIN_PASSWORD"
	TypeSecurityNotes SecretType = "SECURITY_NOTES"
	TypeKeysValues    SecretType = "KEYS_VALUES"
	TypeTwoFactor     SecretType = "TWO_FACTOR"
)

// Format identifies the third-party export format.
type Format string

const (
	FormatAuto      Format = "auto"
	Format1PUX      Format = "1pux"
	FormatBitwarden Format = "bitwarden"
	FormatCSV       Format = "csv"
	FormatEnv       Format = "env"
)

// SupportedFormats defines the list of valid import format identifiers.
var SupportedFormats = []string{
	string(FormatAuto),
	string(Format1PUX),
}

// ImportedSecret is the intermediate normalized representation of a secret ready for Ennote ingestion.
type ImportedSecret struct {
	Name    string
	Type    SecretType
	URL     string
	Labels  []string
	Notes   string
	Payload []byte // Serialized JSON payload matching the Ennote secret type schema
}

// ImportOptions provides filtering and configuration options for importers.
type ImportOptions struct {
	VaultFilter string
}

// Importer defines the interface for parsing third-party secret export sources.
type Importer interface {
	Parse(r io.ReaderAt, size int64, opts ImportOptions) ([]ImportedSecret, error)
}

var (
	ErrUnsupportedFormat = errors.New("unsupported import format")
	ErrEmptyExport       = errors.New("no valid secrets found in export")
)
