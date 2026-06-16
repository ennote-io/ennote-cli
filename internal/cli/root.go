package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "ennote",
	Short: "Ennote Security CLI - The Identity-Driven Secret Manager",
	Long:  `The Ennote CLI provides secure, zero-persistence access to your infrastructure secrets.`,

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		vFlag, _ := cmd.Flags().GetBool("version")
		if cmd.Name() != "version" && !vFlag {
			appCfg := config.Load()
			CheckForUpdates(appCfg.Version)
		}
	},

	Run: func(cmd *cobra.Command, args []string) {
		v, _ := cmd.Flags().GetBool("version")
		if v {
			versionCmd.Run(cmd, args)
			return
		}

		_ = cmd.Help()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolP("version", "v", false, "Print the CLI version and check for updates")

}
func initConfig() {
	home, err := os.UserHomeDir()
	if err == nil {
		viper.AddConfigPath(filepath.Join(home, ".config", "ennote"))
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("ENNOTE")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
	}
}

func GetResolvedContext() (string, string, error) {
	orgID := viper.GetString("organization_id")
	workspaceID := viper.GetString("workspace_id")

	if orgID == "" || workspaceID == "" {
		return "", "", fmt.Errorf("organization-id and workspace-id are required. Set them via flags, ENNOTE_ environment variables, or 'ennote config set'")
	}

	return orgID, workspaceID, nil
}
