package main

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

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
