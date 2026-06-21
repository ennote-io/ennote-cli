package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/ennote-io/ennote-cli/internal/crypto"
	"github.com/ennote-io/ennote-cli/internal/grpc"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
	"github.com/ennote-io/ennote-cli/internal/secrets"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var getCmd = &cobra.Command{
	Use:   "get <secret-query> [-- <command>]",
	Short: "Retrieve a secret and print it, or inject it into a child process",
	Long: `Fetch a secret from the Ennote platform. You can either print it to standard output, 
or inject it directly into the environment variables of a child process.
	
Syntax for the secret query:
  <name>                  (Fetches latest version)
  <name>@<version>        (Fetches specific version)
  <name>:<key>            (Fetches latest version, targets specific key)
  <name>@<version>:<key>  (Fetches specific version, targets specific key)`,
	Example: `  # Print secret to console
  ennote secret get "stripe"
  ennote secret get "database@5:password"

  # Inject secret into a command
  ennote secret get "stripe" -- npm run dev
  ennote secret get "aws" -- aws s3 ls`,
	SilenceUsage: true,
	Args:         cobra.MinimumNArgs(1),
	RunE:         runGetCommand,
}

func init() {
	getCmd.Flags().String("organization-id", "", "Target Organization ID (Overrides config/env)")
	getCmd.Flags().String("workspace-id", "", "Target Workspace ID (Overrides config/env)")

	secretCmd.AddCommand(getCmd)
}

func runGetCommand(cmd *cobra.Command, args []string) error {
	orgID, _ := cmd.Flags().GetString("organization-id")
	if orgID == "" {
		orgID = viper.GetString("organization_id")
	}

	workspaceID, _ := cmd.Flags().GetString("workspace-id")
	if workspaceID == "" {
		workspaceID = viper.GetString("workspace_id")
	}

	if orgID == "" || workspaceID == "" {
		return fmt.Errorf("organization-id and workspace-id are required context. Set them via flags, ENNOTE_ environment variables, or 'ennote config set'")
	}

	secretQuery := args[0]

	var processArgs []string
	if len(args) > 1 {
		processArgs = args[1:]
	}

	name, version, targetKey, err := parseSecretQuery(secretQuery)
	if err != nil {
		return err
	}

	appConfig := config.Load()
	keyring := config.NewOSKeyring()
	envToken := os.Getenv("ENNOTE_TOKEN")

	conn, err := grpc.NewSecureClient(appConfig.BackendURL, keyring, appConfig.Version, envToken)
	if err != nil {
		return fmt.Errorf("failed to initialize gRPC client: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	client := clipb.NewCliServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	plaintextJSON, err := secrets.FetchAndDecapsulate(ctx, client, orgID, workspaceID, name, version)
	if err != nil {
		if st, ok := status.FromError(errors.Unwrap(err)); ok {
			if st.Code() == codes.Unauthenticated {
				return fmt.Errorf("unauthorized: your session is invalid or expired. Please run 'ennote auth login' to authenticate")
			}
			return errors.New(st.Message())
		}
		return err
	}
	defer crypto.ZeroMemory(plaintextJSON)

	if len(processArgs) > 0 {
		envVars, err := extractEnvVars(plaintextJSON, targetKey)
		if err != nil {
			return err
		}
		return executeWithEnv(processArgs, envVars)
	}

	return outputDecryptedData(plaintextJSON, targetKey)
}

func parseSecretQuery(query string) (name string, version *int32, targetKey string, err error) {
	parts := strings.SplitN(query, ":", 2)
	if len(parts) == 2 {
		targetKey = parts[1]
		query = parts[0]
	}

	parts = strings.SplitN(query, "@", 2)
	name = parts[0]
	if len(parts) == 2 {
		v, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return "", nil, "", fmt.Errorf("invalid version format, must be an integer: %w", err)
		}
		version = new(int32(v))
	}

	if name == "" {
		return "", nil, "", fmt.Errorf("secret name cannot be empty")
	}

	return name, version, targetKey, nil
}

func serializeEnvValue(v interface{}) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case float64:
		return fmt.Sprintf("%v", val), nil
	case bool:
		return fmt.Sprintf("%v", val), nil
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

func extractEnvVars(plaintextJSON []byte, targetKey string) (map[string]string, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(plaintextJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted JSON payload: %w", err)
	}

	envVars := make(map[string]string)

	if targetKey != "" {
		if val, exists := payload[targetKey]; exists {
			strVal, err := serializeEnvValue(val)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize target key: %w", err)
			}
			envVars[targetKey] = strVal
			return envVars, nil
		}
		if kvObj, exists := payload["keysValues"]; exists {
			if kvMap, ok := kvObj.(map[string]interface{}); ok {
				if val, nestedExists := kvMap[targetKey]; nestedExists {
					strVal, err := serializeEnvValue(val)
					if err != nil {
						return nil, fmt.Errorf("failed to serialize target key: %w", err)
					}
					envVars[targetKey] = strVal
					return envVars, nil
				}
			}
		}
		return nil, fmt.Errorf("key %q not found in the decrypted secret payload", targetKey)
	}

	if kvObj, exists := payload["keysValues"]; exists {
		if kvMap, ok := kvObj.(map[string]interface{}); ok {
			for k, v := range kvMap {
				strVal, err := serializeEnvValue(v)
				if err == nil {
					envVars[k] = strVal
				}
			}
			return envVars, nil
		}
	}

	for k, v := range payload {
		if k == "securityNotes" {
			continue
		}
		strVal, err := serializeEnvValue(v)
		if err == nil {
			envVars[k] = strVal
		}
	}

	return envVars, nil
}

func outputDecryptedData(plaintextJSON []byte, targetKey string) error {
	var payload map[string]interface{}
	if err := json.Unmarshal(plaintextJSON, &payload); err != nil {
		return fmt.Errorf("failed to parse decrypted JSON payload: %w", err)
	}

	if targetKey != "" {
		if val, exists := payload[targetKey]; exists {
			fmt.Println(val)
			return nil
		}

		if kvObj, exists := payload["keysValues"]; exists {
			if kvMap, ok := kvObj.(map[string]interface{}); ok {
				if val, nestedExists := kvMap[targetKey]; nestedExists {
					fmt.Println(val)
					return nil
				}
			}
		}

		return fmt.Errorf("key %q not found in the decrypted secret payload", targetKey)
	}

	if notesVal, exists := payload["securityNotes"]; exists {
		if notesStr, ok := notesVal.(string); ok {
			fmt.Println(notesStr)
			return nil
		}
	}

	printUnescapedJSON := func(data interface{}) error {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return err
		}
		fmt.Print(buf.String())
		return nil
	}

	if kvObj, exists := payload["keysValues"]; exists {
		if kvMap, ok := kvObj.(map[string]interface{}); ok {
			return printUnescapedJSON(kvMap)
		}
	}

	return printUnescapedJSON(payload)
}
