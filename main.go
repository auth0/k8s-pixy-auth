package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/auth0/auth0-kubectl-auth/auth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

func main() {
	issuer := os.Args[1]
	clientID := os.Args[2]
	audience := os.Args[3]

	idToken := getAuthToken(issuer, clientID, audience)

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
}

type tokenProvider interface {
	GetIDToken() (string, error)
}

// getAuthToken
func getAuthToken(issuer, clientID, audience string) string {
	provider := newCachingTokenProviderFromConfigFile(issuer, clientID, audience)

	idToken, err := provider.GetIDToken()
	if err != nil {
		panic(err)
	}

	return idToken
}

func newCachingTokenProviderFromConfigFile(issuer, clientID, audience string) tokenProvider {
	return auth.NewCachingTokenProvider(
		newConfigBackedCachingProvider(clientID, audience, newConfigFromFile()),
		auth.NewDefaultIDTokenProvider(auth.Issuer{
			IssuerEndpoint: issuer,
			ClientID:       clientID,
			Audience:       audience,
		}))
}

type configProvider interface {
	GetTokens(identifier string) (string, string)
	SaveTokens(identifier, idToken, refreshToken string)
}

type configBackedCachingProvider struct {
	identifier string
	config     configProvider
}

func newConfigBackedCachingProvider(clientID, audience string, config configProvider) *configBackedCachingProvider {
	return &configBackedCachingProvider{
		identifier: fmt.Sprintf("%s-%s", clientID, audience),
		config:     config,
	}
}

func (c *configBackedCachingProvider) GetTokens() *auth.TokenResult {
	idToken, refreshToken := c.config.GetTokens(c.identifier)
	return &auth.TokenResult{
		IDToken:      idToken,
		RefreshToken: refreshToken,
	}
}

func (c *configBackedCachingProvider) CacheTokens(toCache *auth.TokenResult) {
	c.config.SaveTokens(c.identifier, toCache.IDToken, toCache.RefreshToken)
}
