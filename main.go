package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

type tokenCache interface {
	GetTokens(clientID string) (string, string)
	CacheTokens(clientID, idToken, refreshToken string)
}

// getAuthToken
func getAuthToken(domain, clientID, audience string) string {
	//todo: redo config
	//config := newConfigFromFile()
	//idToken, refreshToken := config.GetTokens(clientID)

	// if idToken != "" && refreshToken != "" {
	// 	if !IsTokenExpired(idToken) {
	// 		return idToken
	// 	}

	// 	idToken = refreshTokenExchangeFlow(domain, clientID, refreshToken)
	// } else {
	//todo: reimplement refresh token flow
	tokenResult := pkceFlow(domain, clientID, audience)
	idToken := tokenResult.IDToken
	//}

	//config.CacheTokens(clientID, idToken, refreshToken)

	return idToken
}

// IsTokenExpired ...
func IsTokenExpired(token string) bool {
	p := jwt.Parser{}

	// since we are just getting the expiration time we can unsafely parse
	claims := jwt.MapClaims{}
	_, _, err := p.ParseUnverified(token, claims)
	if err != nil {
		panic(fmt.Errorf("could not parse jwt token: %s", err))
	}

	return !claims.VerifyExpiresAt(time.Now().Unix(), true)
}
