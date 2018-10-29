package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/auth0/auth0-kubectl-auth/auth"
	"github.com/auth0/auth0-kubectl-auth/config"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

func init() {
	rootCmd.AddCommand(authCmd)
}

type tokenProvider interface {
	GetIDToken() (string, error)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Retrieve auth credentials for k8s",
	Long:  "Authenticates using either the browser or cache. Prints out the kubernetes formated auth info object.",
	Run: func(cmd *cobra.Command, args []string) {
		provider := newCachingTokenProviderFromConfigFile(issuerEndpoint, clientID, audience)

		idToken, err := provider.GetIDToken()
		if err != nil {
			panic(err)
		}

		creds := v1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &v1beta1.ExecCredentialStatus{
				Token: idToken,
			},
		}

		jCreds, _ := json.Marshal(creds)
		fmt.Println(string(jCreds))
	},
}

func newCachingTokenProviderFromConfigFile(issuer, clientID, audience string) tokenProvider {
	return auth.NewCachingTokenProvider(
		auth.NewConfigBackedCachingProvider(clientID, audience, config.NewConfigFromFile()),
		auth.NewDefaultIDTokenProvider(auth.Issuer{
			IssuerEndpoint: issuer,
			ClientID:       clientID,
			Audience:       audience,
		}))
}
