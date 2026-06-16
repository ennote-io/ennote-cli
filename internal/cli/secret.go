package cli

import (
	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage and access Ennote secrets",
	Long:  `The secret command group provides commands for retrieving and injecting secrets.`,
}

func init() {
	rootCmd.AddCommand(secretCmd)
}
