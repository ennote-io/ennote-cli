package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/ennote-io/ennote-cli/internal/crypto"
	"github.com/ennote-io/ennote-cli/internal/grpc"
	clipb "github.com/ennote-io/ennote-cli/internal/grpc/pb"
	"github.com/spf13/cobra"
	grpc2 "google.golang.org/grpc"
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Create and read Zero-Knowledge encrypted secret links",
}

var shareCreateCmd = &cobra.Command{
	Use:   "create [secret-text]",
	Short: "Create a self-destructing, encrypted share link",
	Example: `  ennote share create "my-super-secret"
  echo "secret-from-pipe" | ennote share create
  cat config.json | ennote share create --ttl 7d --password "1234"`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var plaintext string

		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			bytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read from standard input: %w", err)
			}
			plaintext = string(bytes)

			plaintext = strings.TrimSuffix(plaintext, "\n")
			plaintext = strings.TrimSuffix(plaintext, "\r")
		} else {
			if len(args) == 0 {
				return fmt.Errorf("you must provide a secret either as an argument or via stdin pipe")
			}
			plaintext = args[0]
		}

		if len(strings.TrimSpace(plaintext)) == 0 {
			return fmt.Errorf("secret content cannot be empty")
		}

		if len([]rune(plaintext)) > 10000 {
			return fmt.Errorf("secret exceeds the maximum allowed length of 10000 characters")
		}

		ttlStr, _ := cmd.Flags().GetString("ttl")
		password, _ := cmd.Flags().GetString("password")

		ttlMinutes, err := parseTTL(ttlStr)
		if err != nil {
			return err
		}

		appConfig := config.Load()

		fmt.Println("Encrypting payload locally...")
		encryptedBlob, passwordHash, salt, key, err := crypto.EncryptOnetime(plaintext, password)
		if err != nil {
			return fmt.Errorf("local encryption failed: %w", err)
		}

		conn, err := grpc.NewPublicClient(appConfig.BackendURL)
		if err != nil {
			return fmt.Errorf("failed to initialize public gRPC client: %w", err)
		}
		defer conn.Close()

		client := clipb.NewCliServiceClient(conn)

		req := &clipb.PutCliShareDataRequest{
			EncryptedBlob: encryptedBlob,
			Ttl:           ttlMinutes,
		}
		if passwordHash != "" {
			req.PasswordHash = &passwordHash
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.PutCliShareData(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to upload encrypted share: %w", err)
		}

		hashFragment := key
		if salt != "" {
			hashFragment += "_" + salt
		}

		baseURL := "https://app.ennote.io/onetime"

		finalURL := fmt.Sprintf("%s/%s#%s", baseURL, resp.Id, hashFragment)

		fmt.Println("\nSecure Share Created Successfully!")
		fmt.Printf("Link: %s\n", finalURL)
		fmt.Println("\n⚠️  WARNING: The decryption key is embedded in the link. Do not lose it.")
		if password != "" {
			fmt.Println("This link is protected by a secondary password.")
		}
		fmt.Printf("⏳ Expires in: %s\n", ttlStr)

		return nil
	},
}

var shareGetCmd = &cobra.Command{
	Use:   "get <url> [-- <command>]",
	Short: "Decrypt and read a secure share link, optionally injecting it into a process",
	Example: `  # Read full payload to standard output
  ennote share get "https://app.ennote.io/onetime/1234"

  # Extract a specific JSON field from a shared payload
  ennote share get "https://app.ennote.io/onetime/1234" --key "password"
  ennote share get "https://app.ennote.io/onetime/1234" -k "password"
  
  # Inject only a specific key into a child process
  ennote share get "https://app.ennote.io/onetime/1234" --key "password" -- ./deploy.sh`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputURL := args[0]
		password, _ := cmd.Flags().GetString("password")
		targetKey, _ := cmd.Flags().GetString("key")

		targetKey = strings.TrimPrefix(targetKey, "keysValues.")

		var processArgs []string
		if len(args) > 1 {
			processArgs = args[1:]
		}

		u, err := url.Parse(inputURL)
		if err != nil {
			return fmt.Errorf("invalid URL format: %w", err)
		}

		uuid := path.Base(u.Path)
		fragment := u.Fragment
		if fragment == "" {
			return fmt.Errorf("link is corrupted: missing decryption key in URL fragment (#)")
		}

		parts := strings.Split(fragment, "_")
		key := parts[0]
		var salt string
		if len(parts) > 1 {
			salt = parts[1]
		}

		appConfig := config.Load()
		conn, err := grpc.NewPublicClient(appConfig.BackendURL)
		if err != nil {
			return fmt.Errorf("failed to initialize public gRPC client: %w", err)
		}
		defer func(conn *grpc2.ClientConn) {
			_ = conn.Close()
		}(conn)

		client := clipb.NewCliServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var passwordHash string
		if salt != "" {
			if password == "" {
				return fmt.Errorf("this share is password protected. Please provide the --password flag")
			}
			passwordHash, err = crypto.DerivePasswordHash(password, salt)
			if err != nil {
				return fmt.Errorf("failed to derive password hash: %w", err)
			}
		}

		req := &clipb.GetCliShareDataRequest{
			Id: uuid,
		}
		if passwordHash != "" {
			req.PasswordHash = &passwordHash
		}

		resp, err := client.GetCliShareData(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to fetch share (it may have been read already or expired): %w", err)
		}

		plaintext, err := crypto.DecryptOnetime(resp.EncryptedBlob, key)
		if err != nil {
			return fmt.Errorf("local decryption failed: %w", err)
		}

		var payload map[string]interface{}
		isJSON := json.Unmarshal([]byte(plaintext), &payload) == nil

		if targetKey != "" && !isJSON {
			return fmt.Errorf("cannot extract key %q: decrypted share is not valid JSON", targetKey)
		}

		if len(processArgs) > 0 {
			var envVars map[string]string
			if isJSON {
				envVars, err = extractEnvVars([]byte(plaintext), targetKey)
				if err != nil {
					return err
				}
			} else {
				envVars = map[string]string{
					"ENNOTE_SHARE_SECRET": plaintext,
				}
			}
			return executeWithEnv(processArgs, envVars)
		}

		fmt.Println("Secret Decrypted Successfully (Burned on Server)")

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

			return fmt.Errorf("key %q not found in the decrypted JSON payload", targetKey)
		}

		fmt.Println(plaintext)
		return nil
	},
}

func parseTTL(s string) (int64, error) {
	if s == "" {
		return 60, nil
	}

	var totalSeconds int64

	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		totalSeconds = val
	} else {
		unit := s[len(s)-1:]
		valStr := s[:len(s)-1]
		val, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil || val <= 0 {
			return 0, fmt.Errorf("invalid TTL format. Examples: 300, 15m, 1h, 7d, 2w")
		}

		var multiplier int64
		switch unit {
		case "s":
			multiplier = 1
		case "m":
			multiplier = 60
		case "h":
			multiplier = 3600
		case "d":
			multiplier = 86400
		case "w":
			multiplier = 604800
		default:
			return 0, fmt.Errorf("unknown time unit '%s'. Use s, m, h, d, or w", unit)
		}
		totalSeconds = val * multiplier
	}

	totalMinutes := totalSeconds / 60

	if totalSeconds%60 != 0 {
		totalMinutes++
	}

	if totalMinutes < 1 {
		totalMinutes = 1
	}

	if totalMinutes > 43200 {
		return 0, fmt.Errorf("TTL cannot exceed 30 days")
	}

	return totalMinutes, nil
}

func init() {
	shareCreateCmd.Flags().String("ttl", "1h", "Time-to-live for the secret (e.g., 30s, 15m, 1h, 7d, 2w). Max 30d.")

	shareCreateCmd.Flags().StringP("password", "p", "", "Optional password to further protect the share")

	shareGetCmd.Flags().StringP("password", "p", "", "Password required to unlock the share (if configured)")

	shareGetCmd.Flags().StringP("key", "k", "", "Extract a specific key from a JSON payload")

	shareCmd.AddCommand(shareCreateCmd)
	shareCmd.AddCommand(shareGetCmd)

	rootCmd.AddCommand(shareCmd)
}
