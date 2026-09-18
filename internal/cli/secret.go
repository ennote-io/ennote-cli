package cli

import (
	"github.com/spf13/cobra"
)

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage and access Ennote secrets",
	}
	cmd.PersistentFlags().String("organization-id", "", "Target Organization ID (overrides config/env)")
	cmd.PersistentFlags().String("workspace-id", "", "Target Workspace ID (overrides config/env)")

	return cmd
}

var secretCmd = newSecretCmd()

func init() {
	rootCmd.AddCommand(secretCmd)
}
