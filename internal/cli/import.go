package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/ennote-io/ennote-cli/internal/crypto"
	"github.com/ennote-io/ennote-cli/internal/grpc"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
	"github.com/ennote-io/ennote-cli/internal/importers"
	"github.com/ennote-io/ennote-cli/internal/importers/registry"
	"github.com/spf13/cobra"
)

const (
	defaultBatchSize = 50

	// importTimeout bounds the whole server phase
	importTimeout = 120 * time.Second

	// Default output caps
	maxListedSecrets  = 50
	maxListedWarnings = 20
)

// importOptions is the flag state for one import run
type importOptions struct {
	format      importers.Format
	vaultFilter string
	dryRun      bool
	verbose     bool
}

// parsedExport holds the content of the full parse process
type parsedExport struct {
	provider string
	fileName string
	scope    string
	secrets  []importers.ImportedSecret
	warnings []string
}

// printer emits progress output, discarding write errors: a failed terminal
// write must not abort an import that is already dispatching secrets.
type printer func(format string, args ...any)

func newPrinter(w io.Writer) printer {
	return func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}

func newSecretImportCmd() *cobra.Command {
	opts := &importOptions{format: importers.FormatAuto}

	cmd := &cobra.Command{
		Use:   "import <file-path>",
		Short: "Import secrets from an external file (1Password 1PUX, 1Password CSV, Ennote CSV)",
		Long: `Import and migrate secrets from files into Ennote native secrets (LOGIN_PASSWORD, SECURITY_NOTES, KEYS_VALUES, TWO_FACTOR).

Supported sources:
  - 1Password unencrypted export archives (.1pux)
  - 1Password CSV exports
  - Generic CSV (columns: Name, Type, Value, Login, Password, URL, Labels, Notes)

The format is detected from the file unless --format is given. Run a bulk
import with --dry-run first to review what would be created; the dry run
parses locally and never contacts the server.`,
		Example: `  # Preview an export before importing anything (recommended for bulk imports)
  ennote secret import secrets.csv --dry-run

  # Import a 1Password 1PUX export archive
  ennote secret import export.1pux

  # Import a CSV file
  ennote secret import secrets.csv

  # Force CSV parsing for a file with an unusual extension
  ennote secret import export.txt --format csv

  # Import a single vault from a 1PUX export
  ennote secret import export.1pux --vault "Production"

  # Show every parsed secret and every warning
  ennote secret import secrets.csv --dry-run --verbose`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretImport(cmd, args[0], opts)
		},
	}

	cmd.Flags().VarP(formatValue{&opts.format}, "format", "f", "Export format (1pux, csv, auto)")
	cmd.Flags().StringVar(&opts.vaultFilter, "vault", "", "Filter to a specific vault/folder by name (ignored with a warning for formats without a folder column)")
	cmd.Flags().BoolVarP(&opts.dryRun, "dry-run", "d", false, "Preview secrets to import without sending to server")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "Do not summarize parsed secrets and warnings")

	return cmd
}

// formatValue adapts importers.Format to pflag.Value so an unsupported --format
// is rejected during flag parsing, before any file is opened.
type formatValue struct{ target *importers.Format }

func (f formatValue) String() string { return string(*f.target) }

func (f formatValue) Type() string { return "format" }

func (f formatValue) Set(v string) error {
	format := importers.Format(strings.ToLower(strings.TrimSpace(v)))
	supported := importers.SupportedFormats()
	if !slices.Contains(supported, format) {
		return fmt.Errorf("must be one of %v", supported)
	}
	*f.target = format
	return nil
}

func runSecretImport(cmd *cobra.Command, filePath string, opts *importOptions) error {
	cmd.SilenceUsage = true

	orgID, workspaceID, err := resolveContext(cmd)
	if err != nil {
		return err
	}

	out := newPrinter(cmd.OutOrStdout())
	errOut := newPrinter(cmd.ErrOrStderr())

	export, err := parseExport(filePath, opts, errOut)
	if err != nil {
		return err
	}

	if opts.dryRun {
		writeDryRun(out, export, opts.verbose)
		return nil
	}

	return uploadExport(export, opts, orgID, workspaceID, out, errOut)
}

// parseExport reads and normalizes the export file content
func parseExport(filePath string, opts *importOptions, errOut printer) (parsedExport, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return parsedExport{}, fmt.Errorf("failed to open export file: %w", err)
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return parsedExport{}, fmt.Errorf("failed to stat export file: %w", err)
	}

	importer, err := registry.GetImporter(opts.format, f, stat.Size(), filePath)
	if err != nil {
		return parsedExport{}, err
	}

	// A filter a provider cannot honor would silently widen the import to the
	// whole export, so drop it loudly instead of half-applying it.
	vaultFilter := opts.vaultFilter
	vaultIgnored := vaultFilter != "" && !importer.SupportsVaultFilter()
	if vaultIgnored {
		errOut("Warning: --vault %q ignored: %s exports carry no vault or folder column; every secret in the file will be imported\n",
			vaultFilter, importer.ProviderName())
		vaultFilter = ""
	}

	res, err := importer.Parse(f, stat.Size(), importers.ImportOptions{VaultFilter: vaultFilter})
	if err != nil {
		// A failed parse still carries the diagnostics that explain it.
		if res != nil && len(res.Warnings) > 0 {
			errOut("\nWarnings (%d):\n", len(res.Warnings))
			writeWarnings(errOut, res.Warnings, opts.verbose)
		}
		return parsedExport{}, err
	}

	return parsedExport{
		provider: importer.ProviderName(),
		fileName: filepath.Base(filePath),
		scope:    describeScope(vaultFilter, vaultIgnored, importer.SupportsVaultFilter()),
		// Ensure unique titles before preview or gRPC dispatch.
		secrets:  importers.DeduplicateNames(res.Secrets),
		warnings: res.Warnings,
	}, nil
}

// describeScope builds the scope label shown in the import banner, naming which
// part of the export was read.
func describeScope(vaultFilter string, vaultIgnored, supportsVaultFilter bool) string {
	switch {
	case vaultIgnored:
		return "scope: entire file, --vault ignored"
	case vaultFilter != "":
		return fmt.Sprintf("scope: vault %q", vaultFilter)
	case !supportsVaultFilter:
		return "scope: entire file"
	default:
		return "scope: all vaults"
	}
}

func writeDryRun(out printer, export parsedExport, verbose bool) {
	out("\n[DRY RUN] Detected format: %s\n", export.provider)
	out("\n[DRY RUN] Found %d secret(s) from %s (%s):\n\n", len(export.secrets), export.fileName, export.scope)

	writeSecretList(out, export.secrets, verbose)

	if len(export.warnings) > 0 {
		out("\nWarnings (%d):\n", len(export.warnings))
		writeWarnings(out, export.warnings, verbose)
	}

	out("\nSummary Breakdown:\n")
	writeBreakdown(out, export.secrets)
	out("\nDry run completed successfully. No changes were sent to the server.\n")
}

// writeSecretList previews parsed secrets, capped unless verbose enabled.
func writeSecretList(out printer, secrets []importers.ImportedSecret, verbose bool) {
	listed := len(secrets)
	if !verbose && listed > maxListedSecrets {
		listed = maxListedSecrets
	}
	for i, s := range secrets[:listed] {
		labelStr := ""
		if len(s.Labels) > 0 {
			labelStr = fmt.Sprintf(" [tags: %s]", strings.Join(s.Labels, ", "))
		}
		urlStr := ""
		if s.URL != "" {
			urlStr = fmt.Sprintf(" (URL: %s)", s.URL)
		}
		out("  %3d. %-35s [%-15s]%s%s\n", i+1, s.Name, s.Type, labelStr, urlStr)
	}
	if listed < len(secrets) {
		out("  ... and %d more secrets (use --verbose to show all)\n", len(secrets)-listed)
	}
}

// writeBreakdown reports counts per secret type, ordered by type so repeated
// runs produce identical output.
func writeBreakdown(out printer, secrets []importers.ImportedSecret) {
	counts := make(map[importers.SecretType]int, len(secrets))
	for _, s := range secrets {
		counts[s.Type]++
	}
	for _, sType := range slices.Sorted(maps.Keys(counts)) {
		out("  - %-15s: %d\n", sType, counts[sType])
	}
}

// uploadExport encrypts every payload locally and dispatches it in batches.
func uploadExport(export parsedExport, opts *importOptions, orgID, workspaceID string, out, errOut printer) error {
	out("\nFound %d secret(s) to import from %s (Format: %s). Connecting to Ennote...\n", len(export.secrets), export.fileName, export.provider)

	if len(export.warnings) > 0 {
		errOut("\nWarnings (%d):\n", len(export.warnings))
		writeWarnings(errOut, export.warnings, opts.verbose)
	}

	appConfig := config.Load()
	conn, err := grpc.NewSecureClient(appConfig.BackendURL, config.NewOSKeyring(), appConfig.Version, os.Getenv("ENNOTE_TOKEN"), orgID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to initialize gRPC client: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := clipb.NewCliServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), importTimeout)
	defer cancel()

	cryptoConfig, err := client.GetCryptoConfig(ctx, &clipb.GetCliCryptoConfigRequest{
		OrganizationId: orgID,
		WorkspaceId:    workspaceID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch crypto config: %w", handleGRPCError(err))
	}

	out("Encrypting payloads locally and dispatching to backend...\n")

	reqSecrets, err := encryptSecrets(export.secrets, cryptoConfig, orgID, workspaceID)
	if err != nil {
		return err
	}

	totalImported, err := uploadBatches(ctx, client, reqSecrets, out)
	if err != nil {
		return err
	}

	out("\n✓ Successfully imported %d secret(s) into workspace %s!\n", totalImported, workspaceID)
	out("Breakdown:\n")
	writeBreakdown(out, export.secrets)

	return nil
}

// encryptSecrets builds the wire requests, zeroing each plaintext payload once
// it has been encrypted.
func encryptSecrets(secrets []importers.ImportedSecret, cryptoConfig *clipb.GetCliCryptoConfigResponse, orgID, workspaceID string) ([]*clipb.AddCliSecretRequest, error) {
	reqSecrets := make([]*clipb.AddCliSecretRequest, 0, len(secrets))
	for _, s := range secrets {
		encryptedBlobBase64, err := crypto.EncryptSecretPayload(s.Payload, cryptoConfig)
		crypto.ZeroMemory(s.Payload)
		if err != nil {
			return nil, fmt.Errorf("encryption failed for secret %q: %w", s.Name, err)
		}

		req := &clipb.AddCliSecretRequest{
			Name:           s.Name,
			WorkspaceId:    workspaceID,
			OrganizationId: orgID,
			Type:           string(s.Type),
			EncryptedBlob:  encryptedBlobBase64,
			Labels:         s.Labels,
		}
		if s.Notes != "" {
			notesCopy := s.Notes
			req.Notes = &notesCopy
		}
		if s.URL != "" {
			urlCopy := s.URL
			req.Url = &urlCopy
		}

		reqSecrets = append(reqSecrets, req)
	}
	return reqSecrets, nil
}

func uploadBatches(ctx context.Context, client clipb.CliServiceClient, reqSecrets []*clipb.AddCliSecretRequest, out printer) (int, error) {
	totalImported := 0
	for i := 0; i < len(reqSecrets); i += defaultBatchSize {
		end := min(i+defaultBatchSize, len(reqSecrets))

		resp, err := client.AddMultiCliSecret(ctx, &clipb.AddMultiCliSecretRequest{
			Secrets: reqSecrets[i:end],
		})
		if err != nil {
			return totalImported, fmt.Errorf("batch import failed at items %d-%d: %w", i+1, end, handleGRPCError(err))
		}

		totalImported += len(resp.Secrets)
		out("  ✓ Uploaded batch %d-%d (%d total created)\n", i+1, end, totalImported)
	}
	return totalImported, nil
}

// writeWarnings prints row diagnostics, capped unless verbose: a bulk CSV can
// emit one warning per row.
func writeWarnings(write printer, warnings []string, verbose bool) {
	shown := len(warnings)
	if !verbose && shown > maxListedWarnings {
		shown = maxListedWarnings
	}
	for _, warning := range warnings[:shown] {
		write("  ! %s\n", warning)
	}
	if shown < len(warnings) {
		write("  ... and %d more warnings (use --verbose to show all)\n", len(warnings)-shown)
	}
}

func init() {
	secretCmd.AddCommand(newSecretImportCmd())
}
