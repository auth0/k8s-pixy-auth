package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"github.com/auth0/k8s-pixy-auth/auth"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

func init() {
	rootCmd.AddCommand(authCmd)
}

type tokenProvider interface {
	GetAccessToken() (string, error)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Retrieve auth credentials for k8s",
	Long:  "Authenticates using either the browser or cache. Prints out the kubernetes formated auth info object.",
	RunE: func(cmd *cobra.Command, args []string) error {
		k, err := getK8sKeyringSetup()
		if err != nil {
			return errors.Wrap(err, "could not set up keyring")
		}

		provider := newCachingTokenProviderUsingKeyring(issuerEndpoint, clientID, audience, k)

		accessToken, err := provider.GetAccessToken()
		if err != nil {
			return errors.Wrap(err, "could not get access token for auth")
		}

		creds := v1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &v1beta1.ExecCredentialStatus{
				Token: accessToken,
			},
		}

		jCreds, _ := json.Marshal(creds)
		fmt.Println(string(jCreds))
		return nil
	},
}

func newCachingTokenProviderUsingKeyring(issuer, clientID, audience string, k keyring.Keyring) tokenProvider {
	return auth.NewCachingTokenProvider(
		auth.NewKeyringCachingProvider(clientID, audience, k),
		auth.NewDefaultAccessTokenProvider(auth.Issuer{
			IssuerEndpoint: issuer,
			ClientID:       clientID,
			Audience:       audience,
		}))
}

func getK8sKeyringSetup() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName:              "k8s-pixy-auth",
		KeychainName:             "k8s-pixy-auth",
		KeychainTrustApplication: true,
		FilePasswordFunc:         k8sTerminalPrompt,
		FileDir:                  "~/.k8s-pixy-auth",
	})
}

func k8sTerminalPrompt(prompt string) (string, error) {
	pass := os.Getenv("KEYRING_K8S_PIXY_AUTH_PASSWORD")
	if len(pass) == 0 {
		fmt.Fprint(os.Stderr, "in the future you can set KEYRING_K8S_PIXY_AUTH_PASSWORD to bypass this prompt\n")
		fmt.Fprint(os.Stderr, fmt.Sprintf("%s: ", prompt))
		b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		pass = string(b)
	} else {
		fmt.Fprint(os.Stderr, "using KEYRING_K8S_PIXY_AUTH_PASSWORD\n")
	}

	return pass, nil
}
