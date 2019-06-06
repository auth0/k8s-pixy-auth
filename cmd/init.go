package cmd

import (
	"fmt"

	"github.com/auth0/k8s-pixy-auth/auth"
	"github.com/auth0/k8s-pixy-auth/initialization"
	"github.com/spf13/cobra"
)

var contextName string

func init() {
	initCmd.Flags().StringVarP(&contextName, "context-name", "n", "", "the kube config context name to init for")
	initCmd.MarkFlagRequired("context-name")
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Install the binary and set up kube config to use the binary",
	Long:  `Copies this binary to ~/.k8s-pixy-auth/bin and then sets up kube config to use it to exec auth for the specified context.`,
	Run: func(cmd *cobra.Command, args []string) {
		initializer := initialization.NewDefaultInitializer()

		fmt.Println("Installing binary...")
		binaryLocation, err := initializer.InstallBinary()
		if err != nil {
			panic(err)
		}

		fmt.Println("Updating kube config...")
		err = initializer.UpdateKubeConfig(contextName, binaryLocation, auth.Issuer{
			IssuerEndpoint: issuerEndpoint,
			ClientID:       clientID,
			Audience:       audience,
		}, useIDToken, withRefreshToken)
		if err != nil {
			panic(err)
		}
	},
}
