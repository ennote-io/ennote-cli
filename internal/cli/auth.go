package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/ennote-io/ennote-cli/internal/auth"
	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage Ennote authentication",
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear the active Ennote session from your local machine",
	RunE: func(cmd *cobra.Command, args []string) error {
		keyStore := config.NewOSKeyring()

		err := keyStore.DeleteCredential("ennote", "session")
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				fmt.Println("No active session found. You are already logged out.")
				return nil
			}
			return fmt.Errorf("failed to clear session from secure storage: %w", err)
		}

		fmt.Println("Successfully logged out. Session wiped from OS Keychain.")
		return nil
	},
}

var loginCmd = &cobra.Command{
	Use:          "login",
	Short:        "Authenticate your CLI session via the Ennote Web UI",
	Example:      `  ennote auth login`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		loginURL := "https://app.ennote.io/cli-login"

		fmt.Println("Opening browser to authenticate...")
		if err := openBrowser(loginURL); err != nil {
			fmt.Printf("Could not open browser automatically. Please navigate to:\n%s\n", loginURL)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		token, err := auth.WaitForToken(ctx, 8888)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		fmt.Println("Secure session token received. Saving...")

		keyring := config.NewOSKeyring()
		if err := keyring.StoreCredential("ennote", "session", token); err != nil {
			return fmt.Errorf("failed to save token to secure storage: %w", err)
		}

		fmt.Println("Login successful. Session securely stored in OS Keychain.")
		return nil
	},
}

func init() {
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(authCmd)
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
