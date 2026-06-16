package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ennote-io/ennote-cli/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

const (
	updateCheckFile = "update_cache.json"
	checkInterval   = 24 * time.Hour
	githubRepoAPI   = "https://api.github.com/repos/ennote-io/ennote-cli/releases/latest"
)

type updateCache struct {
	LastCheck     time.Time `json:"last_check"`
	LatestVersion string    `json:"latest_version"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the CLI version and check for updates",
	Run: func(cmd *cobra.Command, args []string) {
		appCfg := config.Load()
		fmt.Printf("Ennote CLI version: %s\n", appCfg.Version)

		if !isTelemetryDisabled() {
			latest := fetchLatestVersion()
			if latest != "" {
				warnIfOutdated(appCfg.Version, latest)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func isTelemetryDisabled() bool {
	val := strings.ToLower(os.Getenv("ENNOTE_DO_NOT_TRACK"))
	return val == "1" || val == "true"
}

func CheckForUpdates(currentVersion string) {
	if isTelemetryDisabled() {
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	cachePath := filepath.Join(home, ".config", "ennote", updateCheckFile)
	var cache updateCache

	data, err := os.ReadFile(cachePath)
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}

	if time.Since(cache.LastCheck) < checkInterval {
		warnIfOutdated(currentVersion, cache.LatestVersion)
		return
	}

	latest := fetchLatestVersion()
	if latest == "" {
		return
	}

	cache.LastCheck = time.Now()
	cache.LatestVersion = latest
	if newData, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(cachePath, newData, 0600)
	}

	warnIfOutdated(currentVersion, latest)
}

func fetchLatestVersion() string {
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequest(http.MethodGet, githubRepoAPI, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ""
	}

	return release.TagName
}

func warnIfOutdated(current, latest string) {
	if !strings.HasPrefix(current, "v") {
		current = "v" + current
	}
	if !strings.HasPrefix(latest, "v") {
		latest = "v" + latest
	}

	if semver.IsValid(current) && semver.IsValid(latest) {
		if semver.Compare(current, latest) < 0 {
			downloadURL := fmt.Sprintf("https://github.com/ennote-io/ennote-cli/releases/tag/%s", latest)

			fmt.Fprintf(os.Stderr, "\n⚠️  NOTICE: A new version of Ennote CLI is available (%s -> %s)\n", current, latest)
			fmt.Fprintln(os.Stderr, "⚠️  Please update to ensure you have the latest security patches.")
			fmt.Fprintf(os.Stderr, "🔗 Download here: %s\n\n", downloadURL)
		}
	}
}
