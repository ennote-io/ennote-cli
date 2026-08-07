package cli

import (
	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage and access Ennote secrets",
}

func init() {
	rootCmd.AddCommand(secretCmd)
}
