package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the version of the running binary
var version string

// commitSHA is the git commit sha the binary was built off of
var commitSHA string

// buildDate is the date that the binary was built
var buildDate string

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version info of the binary",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version:      %s\nCommit SHA:   %s\nBuild Date:   %s\n", version, commitSHA, buildDate)
	},
}
