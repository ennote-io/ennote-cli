package cli

import (
	"context"
	"fmt"
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
	"github.com/spf13/cobra"
)

const defaultBatchSize = 50

var secretImportCmd = &cobra.Command{
	Use:   "import <file-path>",
	Short: "Import secrets from an external file (e.g. 1Password 1PUX)",
	Long:  `Import and migrate secrets from files into Ennote native secrets (LOGIN_PASSWORD, SECURITY_NOTES, KEYS_VALUES, TWO_FACTOR).`,
	Example: `  # Import a 1Password 1PUX export archive
  ennote secret import export.1pux

  # Preview items without importing
  ennote secret import export.1pux --dry-run

  # Import from a specific vault only
  ennote secret import export.1pux --vault "Production"

  # Explicitly specify format
  ennote secret import export.data --format 1pux`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretImport,
}

func runSecretImport(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	filePath := args[0]
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open export file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat export file: %w", err)
	}

	orgID, workspaceID, err := resolveContext(cmd)
	if err != nil {
		return err
	}

	formatStr, _ := cmd.Flags().GetString("format")
	formatStr = strings.ToLower(strings.TrimSpace(formatStr))
	if !slices.Contains(importers.SupportedFormats, formatStr) {
		return fmt.Errorf("invalid format %q: must be one of %v", formatStr, importers.SupportedFormats)
	}

	vaultFilter, _ := cmd.Flags().GetString("vault")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	batchSize := defaultBatchSize

	importer, err := importers.GetImporter(importers.Format(formatStr), f, stat.Size(), filePath)
	if err != nil {
		return err
	}

	secrets, err := importer.Parse(f, stat.Size(), importers.ImportOptions{
		VaultFilter: vaultFilter,
	})
	if err != nil {
		return err
	}

	// Calculate counts by type
	typeCounts := make(map[importers.SecretType]int)
	for _, s := range secrets {
		typeCounts[s.Type]++
	}

	vaultDesc := "all vaults"
	if vaultFilter != "" {
		vaultDesc = fmt.Sprintf("vault %q", vaultFilter)
	}

	if dryRun {
		fmt.Printf("\n[DRY RUN] Found %d secret(s) in %s (%s):\n\n", len(secrets), filepath.Base(filePath), vaultDesc)
		for i, s := range secrets {
			labelStr := ""
			if len(s.Labels) > 0 {
				labelStr = fmt.Sprintf(" [tags: %s]", strings.Join(s.Labels, ", "))
			}
			urlStr := ""
			if s.URL != "" {
				urlStr = fmt.Sprintf(" (URL: %s)", s.URL)
			}
			fmt.Printf("  %3d. %-35s [%-15s]%s%s\n", i+1, s.Name, s.Type, labelStr, urlStr)
		}

		fmt.Printf("\nSummary Breakdown:\n")
		for sType, count := range typeCounts {
			fmt.Printf("  - %-15s: %d\n", sType, count)
		}
		fmt.Printf("\nDry run completed successfully. No changes were sent to the server.\n")
		return nil
	}

	fmt.Printf("\nFound %d secret(s) to import from %s. Connecting to Ennote...\n", len(secrets), filepath.Base(filePath))

	appConfig := config.Load()
	keyring := config.NewOSKeyring()
	envToken := os.Getenv("ENNOTE_TOKEN")

	conn, err := grpc.NewSecureClient(appConfig.BackendURL, keyring, appConfig.Version, envToken, orgID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to initialize gRPC client: %w", err)
	}
	defer conn.Close()

	client := clipb.NewCliServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cryptoConfig, err := client.GetCryptoConfig(ctx, &clipb.GetCliCryptoConfigRequest{
		OrganizationId: orgID,
		WorkspaceId:    workspaceID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch crypto config: %w", handleGRPCError(err))
	}

	fmt.Println("Encrypting payloads locally and dispatching to backend...")

	var reqSecrets []*clipb.AddCliSecretRequest
	for _, s := range secrets {
		encryptedBlobBase64, err := crypto.EncryptSecretPayload(s.Payload, cryptoConfig)
		// Zero plaintext immediately
		crypto.ZeroMemory(s.Payload)
		if err != nil {
			return fmt.Errorf("encryption failed for secret %q: %w", s.Name, err)
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

	// Chunk and send requests
	totalImported := 0
	for i := 0; i < len(reqSecrets); i += batchSize {
		end := i + batchSize
		if end > len(reqSecrets) {
			end = len(reqSecrets)
		}

		chunk := reqSecrets[i:end]
		resp, err := client.AddMultiCliSecret(ctx, &clipb.AddMultiCliSecretRequest{
			Secrets: chunk,
		})
		if err != nil {
			return fmt.Errorf("batch import failed at items %d-%d: %w", i+1, end, handleGRPCError(err))
		}

		totalImported += len(resp.Secrets)
		fmt.Printf("  ✓ Uploaded batch %d-%d (%d total created)\n", i+1, end, totalImported)
	}

	fmt.Printf("\n✓ Successfully imported %d secret(s) into workspace %s!\n", totalImported, workspaceID)
	fmt.Printf("Breakdown:\n")
	for sType, count := range typeCounts {
		fmt.Printf("  - %-15s: %d\n", sType, count)
	}

	return nil
}

func init() {
	secretCmd.AddCommand(secretImportCmd)

	secretImportCmd.Flags().String("organization-id", "", "Target Organization ID")
	secretImportCmd.Flags().String("workspace-id", "", "Target Workspace ID")
	secretImportCmd.Flags().StringP("format", "f", "auto", "Export format (1pux, auto)")
	secretImportCmd.Flags().String("vault", "", "Filter to a specific vault by name or UUID")
	secretImportCmd.Flags().BoolP("dry-run", "d", false, "Preview secrets to import without sending to server")
}
