package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allowedConfigKeys = map[string]string{
	"organization-id": "organization_id",
	"workspace-id":    "workspace_id",
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage local CLI configuration profiles",
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a local configuration value",
	Long:  "Modify your local CLI state. Supported keys are strictly limited to prevent misconfiguration.",
	Example: `  ennote config set organization-id my-organization-id
  ennote config set workspace-id my-workspace-id`,
	ValidArgs: []string{"organization-id", "workspace-id"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("requires exactly 2 arguments (key and value).\n\nSupported keys:\n  - organization-id\n  - workspace-id")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		inputKey := strings.ToLower(args[0])
		value := strings.TrimSpace(args[1])

		internalKey, exists := allowedConfigKeys[inputKey]
		if !exists {
			return fmt.Errorf("invalid configuration key %q.\n\nSupported keys:\n  - organization-id\n  - workspace-id", inputKey)
		}

		if value == "" {
			return fmt.Errorf("value for key %q cannot be empty", inputKey)
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to locate user home directory: %w", err)
		}

		configDir := filepath.Join(home, ".config", "ennote")
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		viper.Set(internalKey, value)

		configPath := filepath.Join(configDir, "config.yaml")
		viper.SetConfigFile(configPath)

		err = viper.WriteConfig()
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "Not Found") {
				if err := viper.SafeWriteConfig(); err != nil {
					return fmt.Errorf("failed to write initial configuration file: %w", err)
				}
			} else {
				return fmt.Errorf("failed to persist configuration updates: %w", err)
			}
		}

		_ = os.Chmod(configPath, 0600)

		fmt.Printf("Successfully updated %s locally.\n", inputKey)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current active configuration parameters",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("--- Active Ennote Configuration ---")
		fmt.Printf("Organization ID: %s\n", viper.GetString("organization_id"))
		fmt.Printf("Workspace ID:    %s\n", viper.GetString("workspace_id"))
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configShowCmd)

	rootCmd.AddCommand(configCmd)
}
