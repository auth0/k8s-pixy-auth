package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var issuerEndpoint string
var clientID string
var audience string
var useIDToken bool
var withRefreshToken bool

func init() {
	rootCmd.PersistentFlags().StringVarP(&issuerEndpoint, "issuer-endpoint", "i", "", "the issuer endpoint")
	rootCmd.MarkFlagRequired("issuer-endpoint")
	rootCmd.PersistentFlags().StringVarP(&clientID, "client-id", "c", "", "the client id")
	rootCmd.MarkFlagRequired("client-id")
	rootCmd.PersistentFlags().StringVarP(&audience, "audience", "a", "", "the audience")
	rootCmd.MarkFlagRequired("audience")
	rootCmd.PersistentFlags().BoolVar(&useIDToken, "use-id-token", false, "if the id token should be used instead of the access token")
	rootCmd.PersistentFlags().BoolVar(&withRefreshToken, "with-refresh-token", false, "if the refresh token should be used / requested")
}

var rootCmd = &cobra.Command{
	Use:   "k8s-pixy-auth",
	Short: "handle k8s client-go exec auth via PKCE auth",
}

// Execute is the entry point for cobra cmd execution
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
