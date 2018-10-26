package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var issuerEndpoint string
var clientID string
var audience string

func init() {
	rootCmd.PersistentFlags().StringVarP(&issuerEndpoint, "issuer-endpoint", "i", "", "the issuer endpoint")
	rootCmd.MarkFlagRequired("issuer-endpoint")
	rootCmd.PersistentFlags().StringVarP(&clientID, "client-id", "c", "", "the client id")
	rootCmd.MarkFlagRequired("client-id")
	rootCmd.PersistentFlags().StringVarP(&audience, "audience", "a", "", "the audience")
	rootCmd.MarkFlagRequired("audience")
}

var rootCmd = &cobra.Command{
	Use:   "auth0-kubectl-auth",
	Short: "handle k8s client-go exec auth via PKCE auth",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
