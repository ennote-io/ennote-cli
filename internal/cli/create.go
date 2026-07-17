package cli

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/ennote-io/ennote-cli/internal/crypto"
	"github.com/ennote-io/ennote-cli/internal/grpc"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
	"github.com/spf13/cobra"
)

var (
	urlRegex  = regexp.MustCompile(`(?i)^(https?://)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|((\d{1,3}\.){3}\d{1,3}))(:\d+)?(/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(#[-a-z\d_]*)?$`)
	ipv4Regex = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]?)(\.|-)){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]?)$`)
	ipv6Regex = regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`)
)

func validateUrlOrIp(value string) error {
	if urlRegex.MatchString(value) || ipv4Regex.MatchString(value) || ipv6Regex.MatchString(value) {
		return nil
	}
	return fmt.Errorf("please enter a valid URL, IPv4, or IPv6 address")
}

var secretCreateCmd = &cobra.Command{
	Use:   "create <secret-name>",
	Short: "Create a new encrypted secret in your workspace",
	Long: `Securely encrypt and store a new secret within your Ennote workspace.
The payload is encrypted entirely client-side before transit, ensuring zero-persistence
of plaintext data. Supports multiple secret types including login credentials,
key-value pairs, two-factor seeds, and secure notes.`,
	Example: `  ennote secret create "prod-db-credentials" --type LOGIN_PASSWORD --login "admin" --password "supersecret"
  cat .env | ennote secret create "stripe-keys" --type KEYS_VALUES
  ennote secret create "github-2fa" --type TWO_FACTOR --value "JBSWY3DPEHPK3PXP"
  ennote secret create "arch-notes" --type SECURITY_NOTES --value "Critical infrastructure details"
  cat id_rsa | ennote secret create "bastion ssh" --type SECURITY_NOTES`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretCreate,
}

func runSecretCreate(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	secretName := args[0]
	secretType, _ := cmd.Flags().GetString("type")

	url, _ := cmd.Flags().GetString("url")
	if url != "" {
		if err := validateUrlOrIp(url); err != nil {
			return err
		}
	}

	orgID, workspaceID, err := resolveContext(cmd)
	if err != nil {
		return err
	}

	var payloadBytes []byte

	switch secretType {
	case "LOGIN_PASSWORD":
		login, _ := cmd.Flags().GetString("login")
		password, _ := cmd.Flags().GetString("password")
		if login == "" || password == "" {
			return fmt.Errorf("--login and --password flags are required for LOGIN_PASSWORD type")
		}
		payloadBytes, err = json.Marshal(map[string]string{
			"login":    login,
			"password": password,
		})

	case "TWO_FACTOR":
		val, _ := cmd.Flags().GetString("value")
		if val == "" {
			return fmt.Errorf("--value flag is required for TWO_FACTOR type")
		}

		cleanSecret := strings.ToUpper(strings.ReplaceAll(val, " ", ""))
		paddedSecret := cleanSecret
		if padLen := len(cleanSecret) % 8; padLen != 0 {
			paddedSecret += strings.Repeat("=", 8-padLen)
		}

		if _, err := base32.StdEncoding.DecodeString(paddedSecret); err != nil {
			return fmt.Errorf("invalid Base32 secret key format")
		}

		payloadBytes, err = json.Marshal(map[string]string{
			"securityCode": cleanSecret,
		})

	case "SECURITY_NOTES":
		payloadVal, _ := cmd.Flags().GetString("value")
		if payloadVal == "" {
			rawBytes, err := readStdinRaw()
			if err != nil || len(rawBytes) == 0 {
				return fmt.Errorf("must provide secret content via --value flag or stdin pipe for SECURITY_NOTES")
			}
			payloadVal = string(rawBytes)
			crypto.ZeroMemory(rawBytes)
		}
		payloadBytes, err = json.Marshal(map[string]string{
			"securityNotes": payloadVal,
		})

	case "KEYS_VALUES":
		envMap, err := parseEnvFromStdin()
		if err != nil {
			return fmt.Errorf("failed to parse KEYS_VALUES from stdin: %w", err)
		}
		if len(envMap) == 0 {
			return fmt.Errorf("no key-value pairs detected. Please pipe a valid .env format into this command")
		}
		payloadBytes, err = json.Marshal(map[string]interface{}{
			"keysValues": envMap,
		})

	default:
		return fmt.Errorf("unsupported secret type: %s", secretType)
	}

	if err != nil {
		return fmt.Errorf("failed to encode JSON payload: %w", err)
	}

	appConfig := config.Load()
	keyring := config.NewOSKeyring()
	envToken := os.Getenv("ENNOTE_TOKEN")

	conn, err := grpc.NewSecureClient(appConfig.BackendURL, keyring, appConfig.Version, envToken, orgID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to initialize gRPC client: %w", err)
	}
	defer conn.Close()

	client := clipb.NewCliServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cryptoConfig, err := client.GetCryptoConfig(ctx, &clipb.GetCliCryptoConfigRequest{
		OrganizationId: orgID,
		WorkspaceId:    workspaceID,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch crypto config: %w", handleGRPCError(err))
	}

	encryptedBlobBase64, err := crypto.EncryptSecretPayload(payloadBytes, cryptoConfig)
	if err != nil {
		return fmt.Errorf("local encryption failed: %w", err)
	}
	defer crypto.ZeroMemory(payloadBytes)

	rawLabels, _ := cmd.Flags().GetString("labels")
	cleanLabels := make([]string, 0)
	if rawLabels != "" {
		parts := strings.Split(rawLabels, ",")
		for _, l := range parts {
			cleaned := strings.TrimSpace(l)
			if cleaned != "" {
				cleanLabels = append(cleanLabels, cleaned)
			}
		}
	}

	reqNotes, _ := cmd.Flags().GetString("notes")

	req := &clipb.AddCliSecretRequest{
		Name:           secretName,
		WorkspaceId:    workspaceID,
		OrganizationId: orgID,
		Type:           secretType,
		EncryptedBlob:  encryptedBlobBase64,
		Labels:         cleanLabels,
	}

	if reqNotes != "" {
		req.Notes = &reqNotes
	}
	if url != "" {
		req.Url = &url
	}

	resp, err := client.AddCliSecret(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create secret on backend: %w", handleGRPCError(err))
	}

	fmt.Printf("\nSecret '%s' created successfully! (ID: %s)\n", resp.Name, resp.Id)
	return nil
}

func readStdinRaw() ([]byte, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return io.ReadAll(os.Stdin)
	}
	return nil, nil
}

func parseEnvFromStdin() (map[string]string, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, fmt.Errorf("no input detected on stdin")
	}

	envMap := make(map[string]string)
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			envMap[key] = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return envMap, nil
}

func init() {
	secretCmd.AddCommand(secretCreateCmd)

	secretCreateCmd.Flags().String("organization-id", "", "Target Organization ID")
	secretCreateCmd.Flags().String("workspace-id", "", "Target Workspace ID")
	secretCreateCmd.Flags().String("type", "", "Type of secret (LOGIN_PASSWORD, KEYS_VALUES, SECURITY_NOTES, TWO_FACTOR)")
	_ = secretCreateCmd.MarkFlagRequired("type")

	secretCreateCmd.Flags().String("login", "", "Login username or email")
	secretCreateCmd.Flags().String("password", "", "Password")
	secretCreateCmd.Flags().String("value", "", "Payload for SECURITY_NOTES or TWO_FACTOR")

	secretCreateCmd.Flags().String("notes", "", "Optional metadata description")
	secretCreateCmd.Flags().String("url", "", "Associated URL for the secret")
	secretCreateCmd.Flags().String("labels", "", "Comma-separated list of labels")
}
