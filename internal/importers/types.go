package importers

import (
	"errors"
	"io"
	"slices"
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
	FormatAuto Format = "auto"
	Format1PUX Format = "1pux"
	FormatCSV  Format = "csv"
)

// supportedFormats is the canonical list of valid import formats, in the order
// they are offered to the user.
var supportedFormats = [...]Format{FormatAuto, Format1PUX, FormatCSV}

// SupportedFormats returns the valid import formats. The slice is a copy, so
// callers cannot reorder or extend the canonical list.
func SupportedFormats() []Format {
	return slices.Clone(supportedFormats[:])
}

// ImportedSecret is the normalized form of one secret, ready for ingestion.
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

// ImportResult groups normalized secrets with non-fatal row diagnostics.
type ImportResult struct {
	Secrets  []ImportedSecret
	Warnings []string
}

// Importer defines the interface for parsing third-party secret export sources.
type Importer interface {
	// ProviderName returns the human-readable source format, surfaced by the CLI.
	ProviderName() string
	// SupportsVaultFilter reports whether the source carries vault or folder
	// information.
	SupportsVaultFilter() bool
	// Parse normalizes the export. A non-nil result may accompany an error:
	// implementations return accumulated Warnings alongside ErrEmptyExport.
	// Secrets in a result returned with an error are partial and are not imported.
	Parse(r io.ReaderAt, size int64, opts ImportOptions) (*ImportResult, error)
}

// Provider is an Importer that self-identifies from a CSV header row.
type Provider interface {
	Importer
	MatchHeaders(headers []string) bool
}

// FileDetector is an Importer that self-identifies from the export container:
// its magic bytes, archive members or file name.
type FileDetector interface {
	Importer
	MatchFile(r io.ReaderAt, size int64, name string) bool
}

var (
	ErrUnsupportedFormat = errors.New("unsupported import format")
	ErrEmptyExport       = errors.New("no valid secrets found in export")
	ErrUnknownCSVFormat  = errors.New("unrecognized CSV export format")
)
