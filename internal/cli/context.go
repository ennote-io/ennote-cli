package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func resolveContext(cmd *cobra.Command) (string, string, error) {
	orgID, _ := cmd.Flags().GetString("organization-id")
	if orgID == "" {
		orgID = viper.GetString("organization_id")
	}

	workspaceID, _ := cmd.Flags().GetString("workspace-id")
	if workspaceID == "" {
		workspaceID = viper.GetString("workspace_id")
	}

	if orgID == "" || workspaceID == "" {
		return "", "", fmt.Errorf("organization-id and workspace-id are required context. Set them via flags, ENNOTE_ environment variables, or 'ennote config set'")
	}

	return orgID, workspaceID, nil
}
