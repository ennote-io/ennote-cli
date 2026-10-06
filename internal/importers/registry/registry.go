// Package registry resolves an export file to a concrete importer.
package registry

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/importers/bitwarden"
	"github.com/ennote-io/ennote-cli/internal/importers/csvutil"
	"github.com/ennote-io/ennote-cli/internal/importers/ennote"
	"github.com/ennote-io/ennote-cli/internal/importers/lastpass"
	"github.com/ennote-io/ennote-cli/internal/importers/onepassword"
)

// fileDetectors holds importers that identify their own container format, tried
// in order before any CSV header sniff. Append new container formats here.
var fileDetectors = []importers.FileDetector{onepassword.NewPUXImporter()}

// strictCSVProviders holds providers whose MatchHeaders requires a
// provider-specific header signature, tried in order before the fallback.
// Precedence comes from this list versus csvFallbackProvider, never from
// position within one slice.
var strictCSVProviders = []importers.Provider{
	onepassword.NewCSVImporter(),
	lastpass.NewCSVImporter(),
	bitwarden.NewCSVImporter(),
}

// csvFallbackProvider is the terminal CSV provider, tried only after every
// strict provider declines. Exactly one provider occupies this slot.
var csvFallbackProvider importers.Provider = ennote.NewCSVImporter()

// GetImporter resolves the importer for an export in a single pass, reading the
// header at most once.
func GetImporter(format importers.Format, r io.ReaderAt, size int64, filePath string) (importers.Importer, error) {
	switch format {
	case importers.Format1PUX:
		return onepassword.NewPUXImporter(), nil
	case importers.FormatCSV:
		return SniffCSVProvider(r, size)
	case importers.FormatAuto, "":
		return detectImporter(r, size, filePath)
	default:
		return nil, fmt.Errorf("%w: %s", importers.ErrUnsupportedFormat, format)
	}
}

// SniffCSVProvider identifies the provider that owns a CSV export from its
// header row
func SniffCSVProvider(r io.ReaderAt, size int64) (importers.Provider, error) {
	headers, err := csvutil.ReadHeader(r, size)
	if err != nil {
		return nil, err
	}

	if provider := matchProvider(headers, strictCSVProviders, csvFallbackProvider); provider != nil {
		return provider, nil
	}

	return nil, fmt.Errorf("%w: headers %v match no known provider", importers.ErrUnknownCSVFormat, headers)
}

// matchProvider applies the precedence rule: a strict provider always outranks
// the fallback.
func matchProvider(headers []string, strict []importers.Provider, fallback importers.Provider) importers.Provider {
	for _, provider := range strict {
		if provider.MatchHeaders(headers) {
			return provider
		}
	}
	if fallback != nil && fallback.MatchHeaders(headers) {
		return fallback
	}
	return nil
}

func detectImporter(r io.ReaderAt, size int64, filePath string) (importers.Importer, error) {
	name := filepath.Base(filePath)
	for _, detector := range fileDetectors {
		if detector.MatchFile(r, size, name) {
			return detector, nil
		}
	}

	provider, err := SniffCSVProvider(r, size)
	if err == nil {
		return provider, nil
	}
	if errors.Is(err, importers.ErrEmptyExport) {
		return nil, err
	}

	return nil, fmt.Errorf("%w: could not auto-detect the format of %s", importers.ErrUnsupportedFormat, name)
}
