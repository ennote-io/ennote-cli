package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

type jwtPayload struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Exp      int64  `json:"exp"`
	Firebase struct {
		SignInProvider string `json:"sign_in_provider"`
	} `json:"firebase"`
}

var statusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"whoami", "info"},
	Short:   "View your current authentication status",
	Example: `  ennote auth status
  ennote auth whoami`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var token string
		tokenSource := "Environment Variable (ENNOTE_TOKEN)"

		token = os.Getenv("ENNOTE_TOKEN")

		if token == "" {
			keyStore := config.NewOSKeyring()
			var err error
			token, err = keyStore.RetrieveCredential("ennote", "session")
			if err != nil {
				if errors.Is(err, keyring.ErrNotFound) {
					fmt.Println("Status: Not logged in")
					return nil
				}
				return fmt.Errorf("failed to access secure storage: %w", err)
			}
			tokenSource = "OS Keyring"
		}

		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return fmt.Errorf("invalid session token format in %s. Try logging in again", tokenSource)
		}

		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Errorf("failed to decode token payload: %w", err)
		}

		var claims jwtPayload
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			return fmt.Errorf("failed to parse token metadata: %w", err)
		}

		expTime := time.Unix(claims.Exp, 0)
		timeRemaining := time.Until(expTime)

		status := "Active"
		if timeRemaining <= 0 {
			status = "Expired"
		}

		fmt.Println("Ennote CLI Authentication Status")
		fmt.Println("--------------------------------")
		fmt.Printf("%-15s %s\n", "Status:", status)
		fmt.Printf("%-15s %s\n", "Source:", tokenSource)

		accountStr := claims.Email
		if claims.Name != "" {
			accountStr = fmt.Sprintf("%s (%s)", claims.Name, claims.Email)
		}
		if accountStr == "" {
			accountStr = "Service Account / API Key"
		}
		fmt.Printf("%-15s %s\n", "Account:", accountStr)

		if claims.Firebase.SignInProvider != "" {
			fmt.Printf("%-15s %s\n", "Provider:", claims.Firebase.SignInProvider)
		}

		if status == "Active" {
			fmt.Printf("%-15s in %s (%s)\n", "Expires:", formatDuration(timeRemaining), expTime.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("%-15s %s\n", "Expired At:", expTime.Format("2006-01-02 15:04:05"))
			fmt.Println("\nYour session has expired. Please run 'ennote auth login' to authenticate.")
		}

		return nil
	},
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func init() {
	authCmd.AddCommand(statusCmd)
}
